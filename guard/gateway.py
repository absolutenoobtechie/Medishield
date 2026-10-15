"""Runtime decision point for execution requests."""

from __future__ import annotations

import hmac
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from server.backend import _GATEWAY_EXECUTION_TOKEN, execute
from server.db import DEFAULT_DB_PATH, get_connection

from .audit import record_audit_event
from .approval import (
    ApprovalAuthenticationError,
    compute_approval_mac,
    parse_approval_action,
)
from .intent import action_hash, canonicalize_action
from .models import Decision, ExecutionRequest, ProtectedAction
from . import sentinel
from .policy import (
    PINNED_DESTINATIONS,
    TOOL_BASELINE_FINGERPRINTS,
    is_role_permitted,
)


_TRUSTED_TOOL_BASELINES = {
    "update_order": {
        "fingerprint": TOOL_BASELINE_FINGERPRINTS["update_order"],
        "destination": PINNED_DESTINATIONS["update_order"],
    }
}


def _model_fields(model_type: Any) -> tuple[str, ...]:
    fields = getattr(model_type, "model_fields", None)
    if fields is None:  # Pydantic v1 compatibility.
        fields = model_type.__fields__
    return tuple(fields)


def _model_dump(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _validate_request(request: ExecutionRequest) -> ExecutionRequest:
    """Revalidate a request so ``model_construct`` cannot bypass strictness."""

    if not isinstance(request, ExecutionRequest):
        raise ValueError("request must use the ExecutionRequest model")
    if getattr(request, "model_extra", None):
        raise ValueError("request contains unexpected fields")
    if not isinstance(request.action, ProtectedAction):
        raise ValueError("request action must use the ProtectedAction model")
    if getattr(request.action, "model_extra", None):
        raise ValueError("request action contains unexpected fields")

    payload = _model_dump(request)
    if set(payload) != set(_model_fields(ExecutionRequest)):
        raise ValueError("request fields do not match the contract")
    try:
        if hasattr(ExecutionRequest, "model_validate"):
            return ExecutionRequest.model_validate(payload)
        return ExecutionRequest.parse_obj(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("request is invalid") from exc


def _decision(
    decision: str,
    rule: str,
    reason: str,
    changed_fields: list[str] | None = None,
    state_changed: bool = False,
) -> Decision:
    return Decision(
        decision=decision,
        rule=rule,
        reason=reason,
        changed_fields=changed_fields or [],
        state_changed=state_changed,
    )


def _blocked(rule: str, reason: str, changed_fields: list[str] | None = None) -> Decision:
    return _decision("blocked", rule, reason, changed_fields)


def _registry_block(result: sentinel.TrustResult) -> Decision:
    """Convert a non-trusted registry result into an auditable block."""

    rule = {
        "drift": "tool registry drift",
        "baseline_invalid": "tool registry baseline invalid",
        "unverifiable": "tool registry unverifiable",
    }.get(result.status, "tool registry unverifiable")
    return _blocked(rule, sentinel.audit_reason(result))


def _risk_for(rule: str) -> str:
    if rule in {
        "intent hash mismatch",
        "destination not pinned",
        "tool description not pinned",
        "tool registry drift",
        "tool registry baseline invalid",
        "tool registry unverifiable",
    }:
        return "high"
    return "medium"


def _request_metadata(request: Any) -> tuple[str, str, str, str | None]:
    if isinstance(request, ExecutionRequest):
        return request.request_id, request.actor_id, request.tool, request.approval_id
    return "invalid-request", "unknown", "unknown", None


def _audit(connection: sqlite3.Connection, request: Any, decision: Decision) -> None:
    """Write an audit event in the same transaction as the outcome."""

    request_id, actor_id, tool, approval_id = _request_metadata(request)
    record_audit_event(
        {
            "time": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "actor": actor_id,
            "tool": tool,
            "action_type": tool,
            "approval_id": approval_id,
            "decision": decision.decision,
            "risk": _risk_for(decision.rule),
            "rule": decision.rule,
            "reason": decision.reason,
            "changed_fields": decision.changed_fields,
            "state_changed": decision.state_changed,
        },
        connection,
    )


def _record_fail_closed(
    connection: sqlite3.Connection,
    request: Any,
    decision: Decision,
    *,
    commit: bool,
) -> Decision:
    """Persist a blocked result when the normal verification transaction failed."""

    try:
        _audit(connection, request, decision)
        if commit:
            connection.commit()
    except (sqlite3.Error, OSError):
        try:
            connection.rollback()
        except sqlite3.Error:
            pass
    return decision


def _parse_expiry(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("approval expiry must include a timezone")
    return parsed.astimezone(timezone.utc)


def _verify_approval_authentication(
    approval: sqlite3.Row,
    *,
    tool: str,
    destination: str,
) -> Decision | None:
    """Verify persisted action integrity and the gateway-only approval MAC."""

    try:
        parse_approval_action(approval["action_json"])
        stored_hash = approval["action_hash"]
        if not isinstance(stored_hash, str) or not hmac.compare_digest(
            stored_hash, action_hash(json.loads(approval["action_json"]))
        ):
            return _blocked(
                "approval invalid",
                "The stored approval action fingerprint is invalid.",
            )
        expected_mac = compute_approval_mac(
            approval_id=approval["approval_id"],
            action_json=approval["action_json"],
            action_hash=stored_hash,
            approver_id=approval["approver_id"],
            created_at=approval["created_at"],
            expires_at=approval["expires_at"],
            tool=tool,
            destination=destination,
        )
        supplied_mac = approval["approval_mac"]
        if not isinstance(supplied_mac, str) or not hmac.compare_digest(
            supplied_mac, expected_mac
        ):
            return _blocked(
                "approval authentication failed",
                "The approval authentication data does not match the trusted record.",
            )
    except ApprovalAuthenticationError:
        return _blocked(
            "approval authentication unavailable",
            "Approval authentication is unavailable, so execution was denied.",
        )
    except (TypeError, ValueError, ArithmeticError, json.JSONDecodeError):
        return _blocked(
            "approval invalid",
            "The stored approval data is malformed or not canonical.",
        )
    return None


def _changed_fields(stored_action_json: str, action: ProtectedAction) -> list[str]:
    """Return canonical protected fields that differ from the approved action."""

    try:
        approved = json.loads(canonicalize_action(json.loads(stored_action_json)))
        submitted = json.loads(canonicalize_action(action))
    except (TypeError, ValueError, ArithmeticError, json.JSONDecodeError):
        return list(_model_fields(ProtectedAction))
    return [field for field in _model_fields(ProtectedAction) if approved[field] != submitted[field]]


def _validate_tool_baseline(
    connection: sqlite3.Connection, tool: str, destination: Optional[str]
) -> Decision | None:
    """Check the immutable policy baseline and an optional persisted baseline."""

    trusted = _TRUSTED_TOOL_BASELINES.get(tool)
    if trusted is None:
        return _blocked("tool not pinned", "The requested tool is not a pinned tool.")
    if not destination or not hmac.compare_digest(destination, trusted["destination"]):
        return _blocked(
            "destination not pinned",
            "The requested destination differs from the trusted baseline.",
        )

    baseline = connection.execute(
        "SELECT fingerprint, allowed_destination FROM tool_baseline WHERE tool_name = ?",
        (tool,),
    ).fetchone()
    # A missing row is unsafe: the database must explicitly pin the tool.
    if baseline is None:
        return _blocked(
            "tool baseline missing",
            "The trusted tool baseline is not registered in the database.",
        )
    if not hmac.compare_digest(baseline["fingerprint"], trusted["fingerprint"]):
        return _blocked(
            "tool description not pinned",
            "The tool fingerprint differs from the trusted baseline.",
        )
    if not hmac.compare_digest(baseline["allowed_destination"], trusted["destination"]):
        return _blocked(
            "destination not pinned",
            "The tool destination differs from the trusted baseline.",
        )
    return None


def _canonical_request(request: ExecutionRequest) -> ExecutionRequest:
    """Use normalized protected values when writing the simulated backend."""

    action_payload = json.loads(canonicalize_action(request.action))
    payload = _model_dump(request)
    payload["action"] = action_payload
    if hasattr(ExecutionRequest, "model_validate"):
        return ExecutionRequest.model_validate(payload)
    return ExecutionRequest.parse_obj(payload)


def _verify_in_transaction(
    connection: sqlite3.Connection, request: ExecutionRequest, destination: Optional[str]
) -> Decision:
    """Apply the documented security checks in order within one transaction."""

    actor = connection.execute(
        "SELECT role FROM actors WHERE actor_id = ?", (request.actor_id,)
    ).fetchone()
    if actor is None:
        return _blocked("actor not registered", "The actor is not in the authorized directory.")
    if not is_role_permitted(request.tool, actor["role"]):
        return _blocked(
            "role not permitted",
            "This actor role is not permitted to execute the requested tool.",
        )

    patient_scope = connection.execute(
        "SELECT org_id FROM patients WHERE patient_id = ?",
        (request.action.patient_id,),
    ).fetchone()
    if patient_scope is None or not patient_scope["org_id"]:
        return _blocked(
            "patient scope unavailable",
            "The protected patient is not registered in an organization scope.",
        )
    actor_scope = connection.execute(
        """
        SELECT 1 FROM memberships
        WHERE org_id = ? AND actor_id = ? AND role = ? AND active = 1
        """,
        (patient_scope["org_id"], request.actor_id, actor["role"]),
    ).fetchone()
    if actor_scope is None:
        return _blocked(
            "tenant scope not permitted",
            "The executing actor is not an active member of the patient's organization.",
        )

    effective_destination = destination if destination is not None else getattr(request, "destination", None)
    baseline_failure = _validate_tool_baseline(connection, request.tool, effective_destination)
    if baseline_failure is not None:
        return baseline_failure

    approval = connection.execute(
        """
        SELECT approval_id, action_hash, action_json, approver_id,
               created_at, expires_at, revoked, consumed, approval_mac
        FROM approvals WHERE approval_id = ?
        """,
        (request.approval_id,),
    ).fetchone()
    if approval is None:
        return _blocked("approval not found", "No approval exists for this request.")
    authentication_failure = _verify_approval_authentication(
        approval,
        tool=request.tool,
        destination=effective_destination,
    )
    if authentication_failure is not None:
        return authentication_failure
    try:
        created_at = _parse_expiry(approval["created_at"])
        expires_at = _parse_expiry(approval["expires_at"])
    except (AttributeError, TypeError, ValueError):
        return _blocked("approval invalid", "The approval timestamps are invalid.")
    if expires_at <= created_at or expires_at <= datetime.now(timezone.utc):
        return _blocked("approval expired", "The approval is outside its validity window.")
    if approval["revoked"]:
        return _blocked("approval revoked", "The clinician approval has been revoked.")
    if approval["consumed"]:
        return _blocked("approval already consumed", "The one-time approval was already used.")

    approver = connection.execute(
        "SELECT role FROM actors WHERE actor_id = ?", (approval["approver_id"],)
    ).fetchone()
    if approver is None or approver["role"] != "clinician":
        return _blocked("approval invalid", "The approval was not issued by a clinician.")
    approver_scope = connection.execute(
        """
        SELECT 1 FROM memberships
        WHERE org_id = ? AND actor_id = ? AND role = 'clinician' AND active = 1
        """,
        (patient_scope["org_id"], approval["approver_id"]),
    ).fetchone()
    if approver_scope is None:
        return _blocked(
            "approval tenant mismatch",
            "The clinician approval is not scoped to the patient's organization.",
        )

    try:
        submitted_hash = action_hash(request.action)
    except (ValueError, ArithmeticError):
        return _blocked("malformed request", "The protected action is invalid.")
    if not hmac.compare_digest(approval["action_hash"], submitted_hash):
        return _blocked(
            "intent hash mismatch",
            "The protected action differs from the clinician approval.",
            _changed_fields(approval["action_json"], request.action),
        )

    consumed = connection.execute(
        """
        UPDATE approvals SET consumed = 1
        WHERE approval_id = ? AND consumed = 0 AND revoked = 0
        """,
        (request.approval_id,),
    ).rowcount
    if consumed != 1:
        return _blocked("approval already consumed", "The one-time approval was already used.")

    execute(
        _canonical_request(request),
        connection,
        _gateway_token=_GATEWAY_EXECUTION_TOKEN,
    )
    return _decision(
        "allowed",
        "intent hash matched",
        "The protected action matched the clinician approval and was executed.",
        state_changed=True,
    )


def verify_execution(
    request: ExecutionRequest,
    connection: Optional[sqlite3.Connection] = None,
    destination: Optional[str] = None,
) -> Decision:
    """Verify, audit, and atomically execute a synthetic approved action."""

    close_after = connection is None
    connection = connection if connection is not None else get_connection(DEFAULT_DB_PATH)
    caller_transaction = connection.in_transaction
    savepoint_name = "medishield_gateway"
    savepoint_active = False
    try:
        try:
            validated_request = _validate_request(request)
        except ValueError:
            return _record_fail_closed(
                connection,
                request,
                _blocked("malformed request", "The execution request is invalid."),
                commit=close_after or not caller_transaction,
            )

        try:
            registry_result = sentinel.check_registry()
        except Exception:
            # Registry inspection is a trust dependency.  Contain failures at
            # this boundary so an SDK or inspection error cannot become an
            # execution success or expose an internal traceback to callers.
            return _record_fail_closed(
                connection,
                validated_request,
                _blocked(
                    "tool registry unverifiable",
                    "The trusted tool registry could not be verified safely.",
                ),
                commit=close_after or not caller_transaction,
            )
        if not registry_result.protected_execution_allowed:
            return _record_fail_closed(
                connection,
                validated_request,
                _registry_block(registry_result),
                commit=close_after or not caller_transaction,
            )

        if caller_transaction:
            # Do not commit a transaction that belongs to the caller. The
            # savepoint still makes the approval/order/audit unit reversible.
            connection.execute(f"SAVEPOINT {savepoint_name}")
            savepoint_active = True
        else:
            connection.execute("BEGIN IMMEDIATE")
        decision = _verify_in_transaction(connection, validated_request, destination)
        _audit(connection, validated_request, decision)
        if caller_transaction:
            connection.execute(f"RELEASE SAVEPOINT {savepoint_name}")
            savepoint_active = False
        else:
            connection.commit()
        return decision
    except (sqlite3.Error, TypeError, ValueError, ArithmeticError, OSError):
        try:
            if savepoint_active:
                connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint_name}")
                connection.execute(f"RELEASE SAVEPOINT {savepoint_name}")
            elif not caller_transaction:
                connection.rollback()
        except sqlite3.Error:
            pass
        return _record_fail_closed(
            connection,
            request,
            _blocked(
                "verification failed",
                "The request could not be verified safely and was not executed.",
            ),
            commit=close_after or not caller_transaction,
        )
    finally:
        if close_after:
            connection.close()

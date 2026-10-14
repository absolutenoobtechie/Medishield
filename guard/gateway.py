"""Runtime decision point for execution requests."""

from __future__ import annotations

import hmac
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from server.backend import execute
from server.db import DEFAULT_DB_PATH, get_connection

from .audit import record_audit_event
from .intent import action_hash, canonicalize_action
from .models import Decision, ExecutionRequest, ProtectedAction
from .policy import PINNED_DESTINATIONS, is_role_permitted


_TRUSTED_TOOL_BASELINES = {
    "update_order": {
        "fingerprint": "sha256:medishield-demo-tool-v1",
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
    except Exception as exc:
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


def _risk_for(rule: str) -> str:
    if rule in {"intent hash mismatch", "destination not pinned", "tool description not pinned"}:
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
    connection: sqlite3.Connection, request: Any, decision: Decision
) -> Decision:
    """Persist a blocked result when the normal verification transaction failed."""

    try:
        _audit(connection, request, decision)
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
    return decision


def _parse_expiry(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("approval expiry must include a timezone")
    return parsed.astimezone(timezone.utc)


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
    # The policy map is the baseline for deployments without a table row. A
    # registered row must match it exactly and cannot override it.
    if baseline is None:
        return None
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

    effective_destination = destination if destination is not None else getattr(request, "destination", None)
    baseline_failure = _validate_tool_baseline(connection, request.tool, effective_destination)
    if baseline_failure is not None:
        return baseline_failure

    approval = connection.execute(
        """
        SELECT action_hash, action_json, approver_id, expires_at, revoked, consumed
        FROM approvals WHERE approval_id = ?
        """,
        (request.approval_id,),
    ).fetchone()
    if approval is None:
        return _blocked("approval not found", "No approval exists for this request.")
    try:
        expires_at = _parse_expiry(approval["expires_at"])
    except (AttributeError, TypeError, ValueError):
        return _blocked("approval invalid", "The approval expiry is invalid.")
    if expires_at <= datetime.now(timezone.utc):
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

    execute(_canonical_request(request), connection)
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
    try:
        try:
            validated_request = _validate_request(request)
        except ValueError:
            return _record_fail_closed(
                connection,
                request,
                _blocked("malformed request", "The execution request is invalid."),
            )

        connection.execute("BEGIN IMMEDIATE")
        decision = _verify_in_transaction(connection, validated_request, destination)
        _audit(connection, validated_request, decision)
        connection.commit()
        return decision
    except (sqlite3.Error, TypeError, ValueError, ArithmeticError):
        connection.rollback()
        return _record_fail_closed(
            connection,
            request,
            _blocked(
                "verification failed",
                "The request could not be verified safely and was not executed.",
            ),
        )
    finally:
        if close_after:
            connection.close()

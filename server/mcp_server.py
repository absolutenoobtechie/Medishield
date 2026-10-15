"""FastMCP tools for the synthetic MediShield clinical backend."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from mcp.server.fastmcp import FastMCP

from guard.gateway import verify_execution
from guard.models import Decision, ExecutionRequest, ProtectedAction
from guard.policy import PINNED_DESTINATIONS
from privacy.auth import AuthorizationError, WorkspaceUser, authenticate_local, require_permission
from server import backend
from server.db import DEFAULT_DB_PATH, get_connection, init_db


DATABASE_PATH = DEFAULT_DB_PATH
UPDATE_ORDER_TOOL = "update_order"
_MAX_PATIENT_RESPONSE_BYTES = 64 * 1024
_MAX_PATIENT_ORDERS = 256
_PATIENT_FIELDS = {"patient_id", "name_synthetic", "org_id"}
_ORDER_FIELDS = {
    "order_id",
    "patient_id",
    "medication_id",
    "dose",
    "units",
    "route",
    "frequency",
    "duration",
}

mcp = FastMCP("MediShield")

_TRUSTED_CONTEXT: ContextVar[WorkspaceUser | None] = ContextVar(
    "medishield_trusted_mcp_context", default=None
)


@contextmanager
def trusted_execution_context(
    connection: sqlite3.Connection,
    actor_id: str,
    org_id: str,
):
    """Establish a server-resolved local-demo identity for one tool call.

    This helper is intentionally not an MCP tool. A real transport adapter must
    establish this context from its authenticated session. Without it, tools
    that read protected records, read security events, create approvals, or
    execute orders fail closed.
    """

    user = authenticate_local(connection, actor_id, org_id)
    token = _TRUSTED_CONTEXT.set(user)
    try:
        yield user
    finally:
        _TRUSTED_CONTEXT.reset(token)


def _trusted_user(connection: sqlite3.Connection, permission: str) -> WorkspaceUser:
    user = _TRUSTED_CONTEXT.get()
    if user is None:
        raise AuthorizationError("an authenticated execution context is required")
    return require_permission(connection, user, permission)


def _context_actor() -> str:
    user = _TRUSTED_CONTEXT.get()
    return user.actor_id if user is not None else "system"


def _audit_context_denial(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    tool: str,
    reason: str,
) -> None:
    """Persist a safe denial event or fail closed if the event cannot be saved."""

    from guard.audit import record_audit_event

    try:
        record_audit_event(
            {
                "time": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
                "actor": _context_actor(),
                "tool": tool,
                "action_type": tool,
                "approval_id": None,
                "decision": "blocked",
                "risk": "high",
                "rule": "authenticated context required",
                "reason": reason,
                "changed_fields": [],
                "state_changed": False,
            },
            connection=connection,
        )
        connection.commit()
    except (sqlite3.Error, OSError, TypeError, ValueError):
        connection.rollback()
        raise PermissionError("Access denied: the security event could not be recorded.") from None


def _model_dump(model: Any) -> dict[str, Any]:
    """Support both Pydantic versions allowed by the project."""

    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _action(action: ProtectedAction | dict[str, Any]) -> ProtectedAction:
    """Validate a tool action using the shared strict contract."""

    if isinstance(action, ProtectedAction):
        return action
    if isinstance(action, dict):
        if hasattr(ProtectedAction, "model_validate"):
            return ProtectedAction.model_validate(action)
        return ProtectedAction.parse_obj(action)
    raise TypeError("action must be a ProtectedAction or object")


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert one configured SQLite row to a JSON-ready dictionary."""

    return {key: row[key] for key in row.keys()}


class ResponseGuardError(ValueError):
    """Raised when a protected tool response is unsafe to release."""


def _validate_patient_response(
    response: Any,
    *,
    patient_id: str,
    org_id: str,
) -> dict[str, Any]:
    """Validate and minimize one patient response before returning it to MCP.

    The backend is trusted to query SQLite, but its returned object is still
    treated as untrusted tool output at the MCP boundary. Internal tenant
    metadata is checked and then omitted from the released patient object.
    Unknown fields, cross-tenant identifiers, malformed values, and oversized
    responses fail closed instead of reaching the agent.
    """

    if not isinstance(response, dict) or set(response) != {"patient", "orders"}:
        raise ResponseGuardError("patient response structure is invalid")
    patient = response["patient"]
    orders = response["orders"]
    if not isinstance(patient, dict) or not isinstance(orders, list):
        raise ResponseGuardError("patient response types are invalid")
    if set(patient) - _PATIENT_FIELDS:
        raise ResponseGuardError("patient response contains unexpected fields")
    if patient.get("patient_id") != patient_id:
        raise ResponseGuardError("patient response identifier does not match the request")
    if not isinstance(patient.get("name_synthetic"), str) or not patient["name_synthetic"]:
        raise ResponseGuardError("patient response name is invalid")
    if patient.get("org_id") != org_id:
        raise ResponseGuardError("patient response tenant scope is invalid")
    if len(orders) > _MAX_PATIENT_ORDERS:
        raise ResponseGuardError("patient response exceeds the order limit")

    safe_orders: list[dict[str, Any]] = []
    for order in orders:
        if not isinstance(order, dict) or set(order) != _ORDER_FIELDS:
            raise ResponseGuardError("patient response order structure is invalid")
        if order.get("patient_id") != patient_id:
            raise ResponseGuardError("patient response order scope is invalid")
        for field, value in order.items():
            if field == "duration":
                if value is not None and not isinstance(value, str):
                    raise ResponseGuardError("patient response order value is invalid")
            elif not isinstance(value, str) or not value:
                raise ResponseGuardError("patient response order value is invalid")
        safe_orders.append(dict(order))

    safe_response = {
        "patient": {
            "patient_id": patient_id,
            "name_synthetic": patient["name_synthetic"],
        },
        "orders": safe_orders,
    }
    try:
        encoded = json.dumps(
            safe_response,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ResponseGuardError("patient response is not JSON-safe") from exc
    if len(encoded) > _MAX_PATIENT_RESPONSE_BYTES:
        raise ResponseGuardError("patient response exceeds the size limit")
    return safe_response


def _audit_response_block(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    actor_id: str,
    reason: str,
) -> None:
    """Record a blocked response release, or fail closed if auditing fails."""

    from guard.audit import record_audit_event

    record_audit_event(
        {
            "time": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "actor": actor_id,
            "tool": "get_patient_record",
            "action_type": "get_patient_record_response",
            "approval_id": None,
            "decision": "blocked",
            "risk": "high",
            "rule": "response validation failed",
            "reason": reason,
            "changed_fields": [],
            "state_changed": False,
        },
        connection=connection,
    )
    connection.commit()


def get_tool_integrity_status() -> dict[str, Any]:
    """Return the read-only Trust Sentinel result for testing and demos."""

    from guard.sentinel import check_registry

    return check_registry().to_dict()


def tamper_runtime_registry(
    tool_name: str = "unexpected_tool",
    description: str = "Synthetic unexpected tool.",
) -> dict[str, Any]:
    """Inject a temporary synthetic tool into the FastMCP server to demonstrate drift."""

    from guard.sentinel import check_registry

    def _unexpected_tool_impl() -> str:
        return "synthetic"

    manager = getattr(mcp, "_tool_manager", None)
    if manager is not None and hasattr(manager, "add_tool"):
        try:
            manager.add_tool(
                _unexpected_tool_impl,
                name=tool_name,
                description=description,
            )
        except Exception:
            pass
    return check_registry().to_dict()


def restore_runtime_registry() -> dict[str, Any]:
    """Restore the FastMCP runtime registry to the canonical expected tools."""

    from guard.sentinel import EXPECTED_TOOL_REGISTRY, check_registry

    expected_names = {item["name"] for item in EXPECTED_TOOL_REGISTRY}
    manager = getattr(mcp, "_tool_manager", None)
    if manager is not None and hasattr(manager, "_tools"):
        for name in list(manager._tools.keys()):
            if name not in expected_names:
                if hasattr(manager, "remove_tool"):
                    manager.remove_tool(name)
                else:
                    manager._tools.pop(name, None)
    return check_registry().to_dict()


@mcp.tool()
def get_patient_record(patient_id: str) -> dict[str, Any]:
    """Return one synthetic patient and that patient's synthetic orders."""

    from guard import sentinel
    from guard.audit import record_audit_event

    try:
        registry_result = sentinel.check_registry()
    except Exception:
        # Tool-registry inspection is a trust dependency. Contain only this
        # dependency failure so no handler or database read is reached.
        try:
            record_audit_event(
                {
                    "time": datetime.now(timezone.utc).isoformat(),
                    "request_id": "REQ-PATIENT-ACCESS",
                    "actor": _context_actor(),
                    "tool": "get_patient_record",
                    "action_type": "get_patient_record",
                    "approval_id": None,
                    "decision": "blocked",
                    "risk": "high",
                    "rule": "tool registry unverifiable",
                    "reason": "The trusted tool registry could not be verified safely.",
                    "changed_fields": [],
                    "state_changed": False,
                },
                db_path=DATABASE_PATH,
            )
        except (sqlite3.Error, OSError, TypeError, ValueError):
            raise PermissionError(
                "Access denied: the security event could not be recorded."
            ) from None
        raise PermissionError(
            "Access denied: the trusted tool registry could not be verified."
        ) from None
    if not registry_result.protected_execution_allowed:
        try:
            rule = {
                "drift": "tool registry drift",
                "baseline_invalid": "tool registry baseline invalid",
                "unverifiable": "tool registry unverifiable",
            }.get(registry_result.status, "tool registry unverifiable")
            record_audit_event(
                {
                    "time": datetime.now(timezone.utc).isoformat(),
                    "request_id": "REQ-PATIENT-ACCESS",
                    "actor": _context_actor(),
                    "tool": "get_patient_record",
                    "action_type": "get_patient_record",
                    "approval_id": None,
                    "decision": "blocked",
                    "risk": "high",
                    "rule": rule,
                    "reason": sentinel.audit_reason(registry_result),
                    "changed_fields": [],
                    "state_changed": False,
                },
                db_path=DATABASE_PATH,
            )
        except (sqlite3.Error, OSError, TypeError, ValueError):
            raise PermissionError(
                "Access denied: the security event could not be recorded."
            ) from None
        raise PermissionError(f"Access denied: {registry_result.explanation}")

    connection = get_connection(DATABASE_PATH)
    try:
        init_db(connection)
        try:
            user = _trusted_user(connection, "patient_read")
        except AuthorizationError as exc:
            _audit_context_denial(
                connection,
                request_id="REQ-PATIENT-AUTH",
                tool="get_patient_record",
                reason="The patient-record request did not carry a valid authenticated organization context.",
            )
            raise PermissionError("Access denied: patient-record authorization failed.") from exc

        scope = connection.execute(
            "SELECT org_id FROM patients WHERE patient_id = ?",
            (patient_id,),
        ).fetchone()
        if scope is None or scope["org_id"] != user.org_id:
            _audit_context_denial(
                connection,
                request_id="REQ-PATIENT-SCOPE",
                tool="get_patient_record",
                reason="The patient record is outside the authenticated organization scope.",
            )
            raise PermissionError("Access denied: patient-record authorization failed.")

        request_id = f"REQ-PATIENT-{uuid.uuid4().hex}"
        patient = backend.get_patient_record(
            patient_id,
            connection=connection,
            trusted_user=user,
        )
        try:
            safe_patient = _validate_patient_response(
                patient,
                patient_id=patient_id,
                org_id=user.org_id,
            )
        except ResponseGuardError as exc:
            try:
                _audit_response_block(
                    connection,
                    request_id=request_id,
                    actor_id=user.actor_id,
                    reason=str(exc),
                )
            except (sqlite3.Error, OSError, TypeError, ValueError):
                connection.rollback()
                raise PermissionError(
                    "Access denied: the response security event could not be recorded."
                ) from None
            raise PermissionError(
                "Access denied: the patient response failed security validation."
            ) from None
        record_audit_event(
            {
                "time": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
                "actor": user.actor_id,
                "tool": "get_patient_record",
                "action_type": "get_patient_record",
                "approval_id": None,
                "decision": "allowed",
                "risk": "medium",
                "rule": "tenant patient-read permission",
                "reason": "Authenticated organization member retrieved a synthetic patient record.",
                "changed_fields": [],
                "state_changed": False,
            },
            connection=connection,
        )
        connection.commit()
        return safe_patient
    except PermissionError:
        raise
    except (sqlite3.Error, OSError, TypeError, ValueError):
        connection.rollback()
        raise PermissionError("Access denied: the patient record could not be retrieved safely.") from None
    finally:
        connection.close()


@mcp.tool()
def propose_medication_order(action: ProtectedAction) -> dict[str, Any]:
    """Validate and return a medication-order proposal without changing state."""

    validated_action = _action(action)
    return {"status": "proposed", "action": _model_dump(validated_action)}


@mcp.tool()
def request_clinician_approval(
    action: ProtectedAction,
    approver_id: str,
    ttl_minutes: float,
) -> dict[str, Any]:
    """Create an approval only from a server-authenticated clinician context."""

    validated_action = _action(action)
    connection = get_connection(DATABASE_PATH)
    try:
        init_db(connection)
        try:
            user = _trusted_user(connection, "approval_confirm")
        except AuthorizationError as exc:
            _audit_context_denial(
                connection,
                request_id="REQ-APPROVAL-AUTH",
                tool="request_clinician_approval",
                reason="Approval creation requires a server-authenticated clinician context.",
            )
            raise PermissionError("Approval denied: clinician confirmation is required.") from exc
        if approver_id != user.actor_id:
            _audit_context_denial(
                connection,
                request_id="REQ-APPROVAL-IDENTITY",
                tool="request_clinician_approval",
                reason="The requested approver does not match the authenticated clinician context.",
            )
            raise PermissionError("Approval denied: approver identity did not match the authenticated context.")
        approval_id = backend.create_approval(
            validated_action,
            user.actor_id,
            ttl_minutes,
            connection=connection,
            trusted_user=user,
        )
        connection.commit()
    except PermissionError:
        raise
    except (sqlite3.Error, OSError, TypeError, ValueError):
        connection.rollback()
        raise
    finally:
        connection.close()
    return {
        "approval_id": approval_id,
        "approver_id": approver_id,
        "status": "pending",
    }


@mcp.tool()
def execute_approved_order(
    request_id: str,
    actor_id: str,
    approval_id: str,
    action: ProtectedAction,
    destination: Optional[str] = None,
) -> dict[str, Any]:
    """Ask the security gateway to verify and execute one approved order.

    This tool constructs the execution request and delegates all protected
    execution to ``verify_execution``. It never calls the backend directly.
    """

    validated_action = _action(action)
    context_connection = get_connection(DATABASE_PATH)
    try:
        init_db(context_connection)
        try:
            user = _trusted_user(context_connection, "clinical_execute")
        except AuthorizationError as exc:
            _audit_context_denial(
                context_connection,
                request_id=request_id,
                tool=UPDATE_ORDER_TOOL,
                reason="Protected execution requires a server-authenticated actor context.",
            )
            raise PermissionError("Execution denied: authenticated actor context is required.") from exc
        if actor_id != user.actor_id:
            _audit_context_denial(
                context_connection,
                request_id=request_id,
                tool=UPDATE_ORDER_TOOL,
                reason="The requested actor does not match the authenticated execution context.",
            )
            raise PermissionError("Execution denied: actor identity did not match the authenticated context.")
    finally:
        context_connection.close()
    actual_destination = destination if destination is not None else PINNED_DESTINATIONS[UPDATE_ORDER_TOOL]
    request = ExecutionRequest(
        request_id=request_id,
        actor_id=actor_id,
        tool=UPDATE_ORDER_TOOL,
        approval_id=approval_id,
        action=validated_action,
        destination=actual_destination,
    )
    decision: Decision = verify_execution(
        request,
        destination=actual_destination,
    )
    return _model_dump(decision)


@mcp.tool()
def get_security_events(limit: int = 20) -> list[dict[str, Any]]:
    """Return security events visible to the authenticated audit role."""

    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit must be a positive integer")

    connection = get_connection(DATABASE_PATH)
    try:
        init_db(connection)
        try:
            user = _trusted_user(connection, "security_events")
        except AuthorizationError as exc:
            _audit_context_denial(
                connection,
                request_id="REQ-SECURITY-EVENTS-AUTH",
                tool="get_security_events",
                reason="Security-event access requires an authorized audit or administrative role.",
            )
            raise PermissionError("Access denied: security-event authorization failed.") from exc
        rows = connection.execute(
            """
            SELECT audit_events.id, audit_events.time, audit_events.request_id,
                   audit_events.actor_id, audit_events.tool, audit_events.action_type,
                   audit_events.approval_id, audit_events.decision, audit_events.risk,
                   audit_events.rule, audit_events.reason,
                   audit_events.changed_fields, audit_events.state_changed
            FROM audit_events
            LEFT JOIN memberships ON memberships.actor_id = audit_events.actor_id
                AND memberships.org_id = ? AND memberships.active = 1
            WHERE audit_events.actor_id = 'system'
               OR memberships.actor_id IS NOT NULL
            ORDER BY id DESC
            LIMIT ?
            """,
            (user.org_id, limit),
        ).fetchall()
        events = []
        for row in rows:
            event = _row_dict(row)
            event["actor"] = event.pop("actor_id")
            event["changed_fields"] = json.loads(event["changed_fields"])
            event["state_changed"] = bool(event["state_changed"])
            event.pop("id")
            events.append(event)
        return events
    finally:
        connection.close()


from guard.sentinel import check_registry, get_trusted_baseline_tools, verify_registry


class PatientDataHandler:
    """Observable telemetry for the already-authorized patient handler."""

    def __init__(self) -> None:
        self.invocation_count = 0
        self.last_patient_id: Optional[str] = None
        self.last_invoked_at: Optional[str] = None
        self.records_accessed: list[str] = []

    def reset_telemetry(self) -> None:
        self.invocation_count = 0
        self.last_patient_id = None
        self.last_invoked_at = None
        self.records_accessed.clear()

    def get_patient_record(
        self,
        patient_id: str,
        connection: Optional[sqlite3.Connection] = None,
        *,
        safe_response: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        if safe_response is None:
            raise PermissionError(
                "PatientDataHandler requires a response validated by the MCP authorization path"
            )
        self.invocation_count += 1
        self.last_patient_id = patient_id
        self.last_invoked_at = datetime.now(timezone.utc).isoformat()
        self.records_accessed.append(patient_id)
        patient = safe_response.get("patient", {})
        return {
            "patient_id": patient_id,
            "name_synthetic": patient.get("name_synthetic", "Synthetic Patient"),
            "status": "active",
            "retrieval_timestamp": self.last_invoked_at,
            "access_classification": "SYNTHETIC_CLINICAL_DEMO",
        }


patient_data_handler = PatientDataHandler()

_active_registry: list[dict[str, Any]] = get_trusted_baseline_tools()


def get_active_registry() -> list[dict[str, Any]]:
    return [dict(t) for t in _active_registry]


def set_active_registry(tools: list[dict[str, Any]]) -> None:
    global _active_registry
    _active_registry = [dict(t) for t in tools]


def reset_active_registry_to_baseline() -> None:
    global _active_registry
    _active_registry = get_trusted_baseline_tools()


def dispatch_mcp_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
    actor_id: str = "agent_1",
    request_id: Optional[str] = None,
    registry_override: Optional[list[dict[str, Any]]] = None,
    connection: Optional[sqlite3.Connection] = None,
) -> dict[str, Any]:
    from guard.audit import record_audit_event

    ts = datetime.now(timezone.utc).isoformat()
    req_id = request_id or f"REQ-MCP-{int(datetime.now().timestamp() * 1000)}"

    if registry_override is None:
        # Normal dispatch must inspect the live FastMCP registry. The mutable
        # active-registry snapshot is retained only for the isolated demo UI.
        sentinel_result = check_registry()
        registry_status = sentinel_result.status.upper()
        registry_allowed = sentinel_result.protected_execution_allowed
        registry_reason = sentinel_result.explanation
        registry_expected_fingerprint = sentinel_result.expected_fingerprint
        registry_observed_fingerprint = sentinel_result.observed_fingerprint
        registry_fingerprints_match = (
            registry_expected_fingerprint is not None
            and registry_observed_fingerprint is not None
            and registry_expected_fingerprint == registry_observed_fingerprint
        )
        registry_differences = sentinel_result.differences
    else:
        # The override is dependency injection for the synthetic tampering
        # demonstration, not a normal-operation trust source.
        sentinel_result = verify_registry(registry_override)
        registry_status = sentinel_result.status
        registry_allowed = sentinel_result.status == "TRUSTED" and sentinel_result.fingerprints_match
        registry_reason = sentinel_result.reason
        registry_expected_fingerprint = sentinel_result.expected_fingerprint
        registry_observed_fingerprint = sentinel_result.observed_fingerprint
        registry_fingerprints_match = sentinel_result.fingerprints_match
        registry_differences = sentinel_result.differences

    close_after = False
    if connection is None:
        connection = get_connection(DATABASE_PATH)
        close_after = True

    try:
        if not registry_allowed:
            record_audit_event(
                {
                    "time": ts,
                    "request_id": req_id,
                    "actor": actor_id,
                    "tool": tool_name,
                    "action_type": f"mcp:{tool_name}",
                    "approval_id": None,
                    "decision": "blocked",
                    "risk": "high",
                    "rule": "registry drift detected",
                    "reason": f"MCP Trust Sentinel detected tool registry drift: {registry_reason}",
                    "changed_fields": registry_differences,
                    "state_changed": False,
                },
                connection=connection,
            )
            if close_after:
                connection.commit()

            return {
                "success": False,
                "request_id": req_id,
                "tool": tool_name,
                "decision": "blocked",
                "rule": "registry drift detected",
                "reason": f"Execution halted fail-closed by MediShield Sentinel: {registry_reason}",
                "sentinel_status": registry_status,
                "expected_fingerprint": registry_expected_fingerprint,
                "observed_fingerprint": registry_observed_fingerprint,
                "fingerprints_match": registry_fingerprints_match,
                "differences": registry_differences,
                "handler_invoked": False,
                "patient_record_returned": None,
                "data": None,
                "state_changed": False,
                "timestamp": ts,
            }

        if tool_name == "get_patient_record":
            patient_id = arguments.get("patient_id")
            if not isinstance(patient_id, str) or not patient_id:
                raise PermissionError("patient-record access requires a valid patient identifier")
            try:
                with trusted_execution_context(connection, actor_id, "ORG-DEMO"):
                    patient_response = get_patient_record(patient_id)
            except (AuthorizationError, PermissionError):
                if close_after:
                    connection.commit()
                return {
                    "success": False,
                    "request_id": req_id,
                    "tool": tool_name,
                    "decision": "blocked",
                    "rule": "patient access denied",
                    "reason": "Authenticated organization permission was required for patient-record access.",
                    "sentinel_status": registry_status,
                    "expected_fingerprint": registry_expected_fingerprint,
                    "observed_fingerprint": registry_observed_fingerprint,
                    "fingerprints_match": registry_fingerprints_match,
                    "differences": registry_differences,
                    "handler_invoked": False,
                    "patient_record_returned": None,
                    "data": None,
                    "state_changed": False,
                    "timestamp": ts,
                }
            patient_record = patient_data_handler.get_patient_record(
                patient_id,
                connection,
                safe_response=patient_response,
            )

            return {
                "success": True,
                "request_id": req_id,
                "tool": tool_name,
                "decision": "allowed",
                "rule": "registry verified",
                "reason": "MCP tool registry verified. Authorized patient record retrieved.",
                "sentinel_status": registry_status,
                "expected_fingerprint": registry_expected_fingerprint,
                "observed_fingerprint": registry_observed_fingerprint,
                "fingerprints_match": registry_fingerprints_match,
                "differences": registry_differences,
                "handler_invoked": True,
                "patient_record_returned": patient_record,
                "data": patient_record,
                "state_changed": False,
                "timestamp": ts,
            }
        elif tool_name == "get_security_events":
            try:
                with trusted_execution_context(connection, actor_id, "ORG-DEMO"):
                    events = get_security_events()
            except (AuthorizationError, PermissionError):
                if close_after:
                    connection.commit()
                return {
                    "success": False,
                    "request_id": req_id,
                    "tool": tool_name,
                    "decision": "blocked",
                    "rule": "security-event access denied",
                    "reason": "An authenticated audit role was required for security-event access.",
                    "sentinel_status": registry_status,
                    "expected_fingerprint": registry_expected_fingerprint,
                    "observed_fingerprint": registry_observed_fingerprint,
                    "fingerprints_match": registry_fingerprints_match,
                    "differences": registry_differences,
                    "handler_invoked": False,
                    "data": None,
                    "state_changed": False,
                    "timestamp": ts,
                }
            return {
                "success": True,
                "request_id": req_id,
                "tool": tool_name,
                "decision": "allowed",
                "rule": "registry verified",
                "reason": "Security events retrieved successfully.",
                "sentinel_status": registry_status,
                "expected_fingerprint": registry_expected_fingerprint,
                "observed_fingerprint": registry_observed_fingerprint,
                "fingerprints_match": registry_fingerprints_match,
                "differences": registry_differences,
                "handler_invoked": True,
                "data": events,
                "state_changed": False,
                "timestamp": ts,
            }
        else:
            return {
                "success": False,
                "request_id": req_id,
                "tool": tool_name,
                "decision": "blocked",
                "rule": "unsupported dispatch path",
                "reason": "This dispatcher does not authorize unreviewed tool execution.",
                "sentinel_status": registry_status,
                "expected_fingerprint": registry_expected_fingerprint,
                "observed_fingerprint": registry_observed_fingerprint,
                "fingerprints_match": registry_fingerprints_match,
                "differences": registry_differences,
                "handler_invoked": False,
                "data": None,
                "state_changed": False,
                "timestamp": ts,
            }
    finally:
        if close_after:
            connection.close()


if __name__ == "__main__":
    mcp.run(transport="stdio")

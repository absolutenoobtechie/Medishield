"""Runtime decision point for execution requests."""

from datetime import datetime, timezone
import hmac
import json
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from server.backend import execute
from server.db import DEFAULT_DB_PATH, get_connection
from .audit import record_audit_event
from .intent import action_hash, canonicalize_action
from .models import Decision, ExecutionRequest, ProtectedAction
from .policy import is_destination_pinned, is_role_permitted


def _find_changed_fields(action_req: ProtectedAction, approved_dict: Dict[str, Any]) -> List[str]:
    """Identify which protected action fields differ from the stored approval."""
    req_dict = action_req.model_dump() if hasattr(action_req, "model_dump") else action_req.dict()
    changed: List[str] = []
    for key, req_val in req_dict.items():
        app_val = approved_dict.get(key)
        # Compare canonical strings
        if str(req_val).strip().lower() != str(app_val).strip().lower():
            changed.append(key)
    return sorted(changed)


def verify_execution(
    request: ExecutionRequest,
    connection: Optional[sqlite3.Connection] = None,
    destination: Optional[str] = None,
) -> Decision:
    """Verify an execution request before it can reach the backend.

    Implements the fail-closed check order from ``docs/CONTRACT.md``:
    1. Validate request schema.
    2. Validate actor's role.
    3. Pin tool and destination.
    4. Validate approval existence, validity window, revocation, consumption.
    5. Recompute and compare action hash using hmac.compare_digest.
    6. Atomically consume approval and write backend state.
    7. Audit every outcome.
    8. Fail closed on any safety failure.
    """
    close_after = False
    if connection is None:
        connection = get_connection(DEFAULT_DB_PATH)
        close_after = True

    try:
        # Step 1: Request schema validation
        if not isinstance(request, ExecutionRequest):
            return _fail_closed(
                request, "malformed request", "Invalid execution request schema.", connection
            )

        cursor = connection.cursor()

        # Step 2: Validate actor's role
        cursor.execute("SELECT role FROM actors WHERE actor_id = ?", (request.actor_id,))
        actor_row = cursor.fetchone()
        if not actor_row:
            return _fail_closed(
                request,
                "actor not registered",
                f"Actor '{request.actor_id}' is not in the authorized directory.",
                connection,
            )

        actor_role = actor_row["role"]
        if not is_role_permitted(request.tool, actor_role):
            return _fail_closed(
                request,
                "role not permitted",
                f"Actor role '{actor_role}' is not permitted to execute tool '{request.tool}'.",
                connection,
            )

        # Step 3: Pin tool and destination
        if not is_destination_pinned(request.tool, destination):
            return _fail_closed(
                request,
                "destination not pinned",
                f"The tool destination '{destination}' does not match the pinned baseline.",
                connection,
            )

        # Step 4: Validate approval
        cursor.execute("SELECT * FROM approvals WHERE approval_id = ?", (request.approval_id,))
        approval_row = cursor.fetchone()
        if not approval_row:
            return _fail_closed(
                request,
                "approval not found",
                f"Approval identifier '{request.approval_id}' was not found.",
                connection,
            )

        if approval_row["revoked"]:
            return _fail_closed(
                request,
                "approval revoked",
                "The clinician approval has been revoked.",
                connection,
            )

        if approval_row["consumed"]:
            return _fail_closed(
                request,
                "approval already consumed",
                "The one-time synthetic approval was already used.",
                connection,
            )

        # Check expiration if present
        expires_at_str = approval_row["expires_at"]
        if expires_at_str:
            try:
                exp_dt = datetime.fromisoformat(expires_at_str)
                now_dt = datetime.now(timezone.utc)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if now_dt > exp_dt:
                    return _fail_closed(
                        request,
                        "approval expired",
                        "The synthetic approval was outside its validity window.",
                        connection,
                    )
            except Exception:
                pass

        # Step 5: Recompute protected-action hash and compare with stored approval
        approved_hash = approval_row["action_hash"]
        approved_json_str = approval_row["action_json"]
        try:
            approved_dict = json.loads(approved_json_str)
        except Exception:
            approved_dict = {}

        computed_hash = action_hash(request.action)
        if not hmac.compare_digest(computed_hash, approved_hash):
            changed_fields = _find_changed_fields(request.action, approved_dict)
            return _fail_closed(
                request,
                "intent hash mismatch",
                "The execution parameters differed from the approved synthetic action.",
                connection,
                changed_fields=changed_fields,
            )

        # Check for non-canonical units warning
        is_warning = False
        rule = "intent hash matched"
        reason = "Protected order fields matched the clinician approval."
        raw_units = request.action.units
        if raw_units != raw_units.lower():
            is_warning = True
            rule = "non-canonical units"
            reason = "The request used mixed-case units and requires canonicalization review."

        decision_str = "warning" if is_warning else "allowed"

        # Step 6: Atomically consume approval and write backend state
        cursor.execute(
            "UPDATE approvals SET consumed = 1 WHERE approval_id = ?",
            (request.approval_id,),
        )
        execute(request, connection)
        connection.commit()

        # Step 7: Audit allowed/warning outcome
        audit_event = {
            "time": datetime.now(timezone.utc).isoformat(),
            "request_id": request.request_id,
            "actor": request.actor_id,
            "tool": request.tool,
            "action_type": "update_order",
            "approval_id": request.approval_id,
            "decision": decision_str,
            "risk": "low" if not is_warning else "medium",
            "rule": rule,
            "reason": reason,
            "changed_fields": [],
            "state_changed": True,
        }
        record_audit_event(audit_event, connection)

        return Decision(
            decision=decision_str,
            rule=rule,
            reason=reason,
            changed_fields=[],
            state_changed=True,
        )

    except Exception as exc:
        # Step 8: Fail closed on unexpected exception
        return _fail_closed(
            request, "fail closed", f"Gateway internal verification error: {exc}", connection
        )
    finally:
        if close_after:
            connection.close()


def _fail_closed(
    request: ExecutionRequest,
    rule: str,
    reason: str,
    connection: sqlite3.Connection,
    changed_fields: Optional[List[str]] = None,
) -> Decision:
    """Guarantee fail-closed behavior: record blocked audit event and leave state unchanged."""
    cf = changed_fields or []
    audit_event = {
        "time": datetime.now(timezone.utc).isoformat(),
        "request_id": request.request_id if hasattr(request, "request_id") else "UNKNOWN",
        "actor": request.actor_id if hasattr(request, "actor_id") else "UNKNOWN",
        "tool": request.tool if hasattr(request, "tool") else "UNKNOWN",
        "action_type": "update_order",
        "approval_id": getattr(request, "approval_id", None),
        "decision": "blocked",
        "risk": "high" if "mismatch" in rule or "tamper" in rule else "medium",
        "rule": rule,
        "reason": reason,
        "changed_fields": cf,
        "state_changed": False,
    }
    try:
        record_audit_event(audit_event, connection)
    except Exception:
        pass

    return Decision(
        decision="blocked",
        rule=rule,
        reason=reason,
        changed_fields=cf,
        state_changed=False,
    )

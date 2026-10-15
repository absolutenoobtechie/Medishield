"""Small, Streamlit-independent helpers for the synthetic dashboard."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from guard.approval import compute_approval_mac
from guard.intent import action_hash, canonicalize_action
from guard.models import Decision, ProtectedAction


def _utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def setup_test_approval(
    connection: sqlite3.Connection,
    approval_id: str,
    action_data: Mapping[str, Any],
    *,
    approver_id: str = "clinician_1",
    created_at: str | None = None,
    expires_at: str | None = None,
) -> str:
    """Create a valid synthetic approval fixture for dashboard demonstrations.

    This uses the same canonicalization, action fingerprint, and gateway secret
    as the backend. It is only a demo-fixture helper; it does not replace the
    normal clinician approval API.
    """

    action = ProtectedAction(**dict(action_data))
    actor = connection.execute(
        "SELECT role FROM actors WHERE actor_id = ?",
        (approver_id,),
    ).fetchone()
    if actor is None or actor["role"] != "clinician":
        raise PermissionError("Synthetic approval fixtures require a clinician approver")
    patient = connection.execute(
        "SELECT org_id FROM patients WHERE patient_id = ?",
        (action.patient_id,),
    ).fetchone()
    if patient is None or not patient["org_id"]:
        raise PermissionError("Synthetic approval fixtures require a scoped patient")
    membership = connection.execute(
        """
        SELECT 1 FROM memberships
        WHERE org_id = ? AND actor_id = ? AND role = 'clinician' AND active = 1
        """,
        (patient["org_id"], approver_id),
    ).fetchone()
    if membership is None:
        raise PermissionError("The clinician is not active in the patient's organization")
    action_json = canonicalize_action(action)
    digest = action_hash(action)
    created = created_at or _utc_timestamp(datetime.now(timezone.utc))
    expires = expires_at or "2026-12-31T23:59:59Z"
    approval_mac = compute_approval_mac(
        approval_id=approval_id,
        action_json=action_json,
        action_hash=digest,
        approver_id=approver_id,
        created_at=created,
        expires_at=expires,
    )
    connection.execute(
        """
        INSERT INTO approvals(
            approval_id, action_hash, action_json, approver_id, created_at,
            expires_at, revoked, consumed, approval_mac
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
        ON CONFLICT(approval_id) DO UPDATE SET
            action_hash = excluded.action_hash,
            action_json = excluded.action_json,
            approver_id = excluded.approver_id,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at,
            revoked = 0,
            consumed = 0,
            approval_mac = excluded.approval_mac
        """,
        (
            approval_id,
            digest,
            action_json,
            approver_id,
            created,
            expires,
            approval_mac,
        ),
    )
    connection.commit()
    return digest


def gateway_verdict(
    decision: Decision | None,
    error: BaseException | None = None,
) -> dict[str, Any]:
    """Convert the real gateway result into a safe, display-ready verdict."""

    if error is not None or not isinstance(decision, Decision):
        return {
            "label": "BLOCKED",
            "decision": "blocked",
            "rule": "verification failed",
            "reason": "Gateway verification could not complete safely.",
            "changed_fields": [],
            "state_changed": False,
            "authorized": False,
            "execution_complete": False,
        }

    if decision.decision == "allowed":
        return {
            "label": "ALLOWED",
            "decision": decision.decision,
            "rule": decision.rule,
            "reason": decision.reason,
            "changed_fields": list(decision.changed_fields),
            "state_changed": bool(decision.state_changed),
            "authorized": True,
            "execution_complete": bool(decision.state_changed),
        }

    label = "WARNING" if decision.decision == "warning" else "BLOCKED"
    return {
        "label": label,
        "decision": decision.decision,
        "rule": decision.rule,
        "reason": decision.reason,
        "changed_fields": list(decision.changed_fields),
        "state_changed": bool(decision.state_changed),
        "authorized": False,
        "execution_complete": False,
    }

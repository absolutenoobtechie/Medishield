"""Dashboard-to-gateway approval and verdict regression tests."""

from __future__ import annotations

import pytest

from dashboard.security_helpers import gateway_verdict, setup_test_approval
from guard import audit
from guard.approval import ApprovalAuthenticationError, compute_approval_mac
from guard.gateway import verify_execution
from guard.intent import action_hash, canonicalize_action
from guard.models import Decision, ExecutionRequest, ProtectedAction
from guard.policy import PINNED_DESTINATIONS
from server.db import initialize_db


DESTINATION = PINNED_DESTINATIONS["update_order"]


def _action(dose: str = "5") -> ProtectedAction:
    return ProtectedAction(
        patient_id="P-104",
        medication_id="MED-A",
        dose=dose,
        units="mg",
        route="oral",
        frequency="daily",
        duration="7 days",
        order_id="ORD-DEMO-001",
    )


@pytest.fixture
def dashboard_database(tmp_path, monkeypatch):
    path = tmp_path / "medishield.sqlite3"
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "logs" / "events.jsonl")
    connection = initialize_db(path)
    yield connection
    connection.close()


def _request(approval_id: str, action: ProtectedAction, request_id: str) -> ExecutionRequest:
    return ExecutionRequest(
        request_id=request_id,
        actor_id="agent_1",
        tool="update_order",
        approval_id=approval_id,
        action=action,
        destination=DESTINATION,
    )


def test_dashboard_fixture_is_accepted_by_real_gateway(dashboard_database):
    action = _action()
    approval_id = "APR-DASH-VALID"
    setup_test_approval(dashboard_database, approval_id, action.model_dump())

    row = dashboard_database.execute(
        """SELECT action_json, action_hash, approver_id, created_at,
                  expires_at, approval_mac
           FROM approvals WHERE approval_id = ?""",
        (approval_id,),
    ).fetchone()
    assert row["action_json"] == canonicalize_action(action)
    assert row["action_hash"] == action_hash(action)
    assert row["approval_mac"] == compute_approval_mac(
        approval_id=approval_id,
        action_json=row["action_json"],
        action_hash=row["action_hash"],
        approver_id=row["approver_id"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
    )

    decision = verify_execution(
        _request(approval_id, action, "REQ-DASH-VALID"),
        dashboard_database,
        destination=DESTINATION,
    )
    assert decision.decision == "allowed"
    assert decision.state_changed is True


def test_dashboard_tampering_and_replay_remain_blocked(dashboard_database):
    action = _action()
    approval_id = "APR-DASH-TAMPER"
    setup_test_approval(dashboard_database, approval_id, action.model_dump())

    tampered = verify_execution(
        _request(approval_id, _action("50"), "REQ-DASH-DOSE-TAMPER"),
        dashboard_database,
        destination=DESTINATION,
    )
    assert tampered.decision == "blocked"
    assert tampered.rule == "intent hash mismatch"
    assert dashboard_database.execute(
        "SELECT consumed FROM approvals WHERE approval_id = ?", (approval_id,)
    ).fetchone()[0] == 0

    dashboard_database.execute(
        "UPDATE approvals SET approval_mac = ? WHERE approval_id = ?",
        ("0" * 64, approval_id),
    )
    dashboard_database.commit()
    bad_mac = verify_execution(
        _request(approval_id, action, "REQ-DASH-BAD-MAC"),
        dashboard_database,
        destination=DESTINATION,
    )
    assert bad_mac.decision == "blocked"
    assert bad_mac.rule == "approval authentication failed"


def test_dashboard_expired_and_consumed_approvals_are_rejected(dashboard_database):
    expired_id = "APR-DASH-EXPIRED"
    setup_test_approval(
        dashboard_database,
        expired_id,
        _action().model_dump(),
        created_at="2019-12-01T00:00:00Z",
        expires_at="2020-01-01T00:00:00Z",
    )
    expired = verify_execution(
        _request(expired_id, _action(), "REQ-DASH-EXPIRED"),
        dashboard_database,
        destination=DESTINATION,
    )
    assert expired.decision == "blocked"
    assert expired.rule == "approval expired"

    consumed_id = "APR-DASH-CONSUMED"
    setup_test_approval(dashboard_database, consumed_id, _action().model_dump())
    first = verify_execution(
        _request(consumed_id, _action(), "REQ-DASH-FIRST"),
        dashboard_database,
        destination=DESTINATION,
    )
    second = verify_execution(
        _request(consumed_id, _action(), "REQ-DASH-SECOND"),
        dashboard_database,
        destination=DESTINATION,
    )
    assert first.decision == "allowed"
    assert second.decision == "blocked"
    assert second.rule == "approval already consumed"


def test_dashboard_fixture_requires_configured_secret(dashboard_database, monkeypatch):
    monkeypatch.delenv("MEDISHIELD_APPROVAL_SECRET", raising=False)

    with pytest.raises(ApprovalAuthenticationError):
        setup_test_approval(dashboard_database, "APR-DASH-NO-SECRET", _action().model_dump())

    assert dashboard_database.execute(
        "SELECT COUNT(*) FROM approvals WHERE approval_id = ?",
        ("APR-DASH-NO-SECRET",),
    ).fetchone()[0] == 0


def test_dashboard_verdict_uses_actual_gateway_decision():
    allowed = gateway_verdict(
        Decision(
            decision="allowed",
            rule="intent hash matched",
            reason="Synthetic action executed.",
            changed_fields=[],
            state_changed=True,
        )
    )
    blocked = gateway_verdict(
        Decision(
            decision="blocked",
            rule="intent hash mismatch",
            reason="Synthetic dose changed.",
            changed_fields=["dose"],
            state_changed=False,
        )
    )
    failed = gateway_verdict(None, RuntimeError("synthetic verification failure"))

    assert allowed["label"] == "ALLOWED"
    assert allowed["authorized"] is True
    assert blocked["label"] == "BLOCKED"
    assert blocked["authorized"] is False
    assert blocked["state_changed"] is False
    assert failed["label"] == "BLOCKED"
    assert failed["decision"] == "blocked"
    assert failed["authorized"] is False
    assert failed["execution_complete"] is False


def test_dashboard_advisory_audit_event_is_schema_compliant(dashboard_database):
    """Verify that the audit event emitted by the advisory simulation button complies strictly with AUDIT_FIELDS."""
    from guard.audit import record_audit_event

    event_payload = {
        "time": "2026-10-15T00:00:00Z",
        "request_id": "REQ-TEST-ADVISORY-001",
        "actor": "agent_1",
        "tool": "update_order",
        "action_type": "medication_order",
        "approval_id": "APR-TEST-ADVISORY-001",
        "decision": "warning",
        "risk": "medium",
        "rule": "unit case normalization notice",
        "reason": "Submitted units 'MG' normalized to lowercase 'mg'. Approved action permitted under clinical oversight.",
        "changed_fields": ["units"],
        "state_changed": True,
    }

    row_id = record_audit_event(event_payload, connection=dashboard_database)
    assert row_id > 0

    saved = dashboard_database.execute(
        "SELECT actor_id, decision, rule, state_changed FROM audit_events WHERE request_id = ?",
        ("REQ-TEST-ADVISORY-001",),
    ).fetchone()
    assert saved is not None
    assert saved["actor_id"] == "agent_1"
    assert saved["decision"] == "warning"
    assert saved["rule"] == "unit case normalization notice"
    assert saved["state_changed"] == 1


def test_dashboard_load_events_empty_database(tmp_path):
    """Verify load_events handles empty database files or tables with 0 rows gracefully."""
    from dashboard.app import load_events

    empty_db = tmp_path / "empty.sqlite3"
    conn = initialize_db(empty_db)
    # Ensure audit_events table exists but has 0 rows
    conn.execute("DELETE FROM audit_events")
    conn.commit()
    conn.close()

    events, source = load_events(db_path=empty_db)
    assert isinstance(events, list)

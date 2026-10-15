"""Focused tests for backend approvals and audit persistence."""

import json
import sqlite3
from types import SimpleNamespace

import pytest

from guard.approval import ApprovalAuthenticationError, compute_approval_mac
from guard.audit import write_event
from guard.intent import action_hash, canonicalize_action
from guard.models import ProtectedAction
from privacy.auth import authenticate_local
from server import backend
from server.db import initialize_db


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"
    monkeypatch.setattr(backend, "DATABASE_PATH", database_path)

    import guard.audit as audit

    monkeypatch.setattr(audit, "DATABASE_PATH", database_path)
    monkeypatch.setattr(audit, "LOG_PATH", log_path)
    return database_path, log_path


def make_action(order_id="ORD-TEST-001"):
    return ProtectedAction(
        patient_id="P-104",
        medication_id="MED-A",
        dose="5.0",
        units="synthetic-units",
        route="simulated-route",
        frequency="demo-only",
        duration="demo-duration",
        order_id=order_id,
    )


def _trusted_user(database_path, actor_id="clinician_1", org_id="ORG-DEMO"):
    connection = initialize_db(database_path)
    try:
        return authenticate_local(connection, actor_id, org_id)
    finally:
        connection.close()


def test_create_approval_stores_canonical_action_and_hash(isolated_database):
    database_path, _ = isolated_database
    action = make_action()

    approval_id = backend.create_approval(
        action,
        "clinician_1",
        5,
        trusted_user=_trusted_user(database_path),
    )

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """SELECT action_json, action_hash, approver_id, created_at,
                      expires_at, approval_mac
               FROM approvals WHERE approval_id = ?""",
            (approval_id,),
        ).fetchone()
    assert row[:3] == (canonicalize_action(action), action_hash(action), "clinician_1")
    assert row[5] == compute_approval_mac(
        approval_id=approval_id,
        action_json=row[0],
        action_hash=row[1],
        approver_id=row[2],
        created_at=row[3],
        expires_at=row[4],
    )


def test_create_approval_fails_closed_without_gateway_secret(
    isolated_database, monkeypatch
):
    database_path, _ = isolated_database
    monkeypatch.delenv("MEDISHIELD_APPROVAL_SECRET", raising=False)

    with pytest.raises(ApprovalAuthenticationError):
        backend.create_approval(
            make_action(),
            "clinician_1",
            5,
            trusted_user=_trusted_user(database_path),
        )

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0


@pytest.mark.parametrize("approver_id", ["missing_actor", "nurse_1", "agent_1"])
def test_create_approval_rejects_non_clinician_or_missing_actor(
    isolated_database, approver_id
):
    database_path, _ = isolated_database
    with pytest.raises((LookupError, PermissionError, ValueError)):
        trusted_actor = approver_id if approver_id != "missing_actor" else "clinician_1"
        backend.create_approval(
            make_action(),
            approver_id,
            5,
            trusted_user=_trusted_user(database_path, trusted_actor),
        )


@pytest.mark.parametrize("ttl_minutes", [0, -1, "not-a-number"])
def test_create_approval_rejects_non_positive_ttl(isolated_database, ttl_minutes):
    database_path, _ = isolated_database
    with pytest.raises(ValueError):
        backend.create_approval(
            make_action(),
            "clinician_1",
            ttl_minutes,
            trusted_user=_trusted_user(database_path),
        )


def test_revoke_approval_marks_existing_row_and_rejects_unknown(isolated_database):
    database_path, _ = isolated_database
    approval_id = backend.create_approval(
        make_action(),
        "clinician_1",
        5,
        trusted_user=_trusted_user(database_path),
    )

    backend.revoke_approval(
        approval_id,
        trusted_user=_trusted_user(database_path),
    )

    with sqlite3.connect(database_path) as connection:
        events = connection.execute(
            """SELECT action_type, approval_id, decision, state_changed
               FROM audit_events ORDER BY id"""
        ).fetchall()

    assert [(row[0], row[1], row[2], row[3]) for row in events] == [
        ("approval_created", approval_id, "allowed", 0),
        ("approval_revoked", approval_id, "allowed", 0),
    ]
    with sqlite3.connect(database_path) as connection:
        revoked = connection.execute(
            "SELECT revoked FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()[0]
    assert revoked == 1

    with pytest.raises(LookupError):
        backend.revoke_approval(
            "APR-UNKNOWN",
            trusted_user=_trusted_user(database_path),
        )


def test_approval_lifecycle_events_are_audited(isolated_database):
    database_path, _ = isolated_database
    approval_id = backend.create_approval(
        make_action(),
        "clinician_1",
        5,
        trusted_user=_trusted_user(database_path),
    )
    backend.revoke_approval(
        approval_id,
        trusted_user=_trusted_user(database_path),
    )


def test_backend_patient_record_requires_authenticated_tenant_context(isolated_database):
    database_path, _ = isolated_database
    connection = initialize_db(database_path)
    try:
        with pytest.raises(PermissionError):
            backend.get_patient_record("P-104", connection=connection)

        user = authenticate_local(connection, "clinician_1", "ORG-DEMO")
        patient = backend.get_patient_record(
            "P-104",
            connection=connection,
            trusted_user=user,
        )
        assert patient["patient"]["patient_id"] == "P-104"

        connection.execute(
            "INSERT OR IGNORE INTO memberships(org_id, actor_id, role, active) VALUES (?, ?, ?, 1)",
            ("ORG-SECOND", "clinician_1", "clinician"),
        )
        connection.commit()
        other_tenant_user = authenticate_local(connection, "clinician_1", "ORG-SECOND")
        with pytest.raises(PermissionError):
            backend.get_patient_record(
                "P-104",
                connection=connection,
                trusted_user=other_tenant_user,
            )
    finally:
        connection.close()

def test_apply_order_uses_caller_transaction(isolated_database):
    database_path, _ = isolated_database
    connection = initialize_db(database_path)
    action = make_action("ORD-TEST-002")

    backend.apply_order(
        action,
        connection=connection,
        _gateway_token=backend._GATEWAY_EXECUTION_TOKEN,
    )
    row = connection.execute(
        "SELECT order_id, patient_id FROM orders WHERE order_id = ?",
        (action.order_id,),
    ).fetchone()
    assert (row["order_id"], row["patient_id"]) == (
        action.order_id,
        action.patient_id,
    )
    connection.rollback()
    connection.close()


def test_apply_order_rejects_missing_connection(isolated_database):
    with pytest.raises(RuntimeError, match="requires the gateway transaction"):
        backend.apply_order(make_action())


def test_apply_order_rejects_direct_caller_without_gateway_capability(isolated_database):
    database_path, _ = isolated_database
    connection = initialize_db(database_path)
    try:
        with pytest.raises(PermissionError, match="restricted to the security gateway"):
            backend.apply_order(make_action(), connection=connection)
    finally:
        connection.close()


def test_backend_execute_cannot_bypass_gateway(isolated_database):
    database_path, _ = isolated_database
    connection = initialize_db(database_path)

    with pytest.raises(PermissionError):
        backend.execute(SimpleNamespace(action=make_action()), connection=connection)

    connection.close()


def test_reinitializing_database_does_not_reset_existing_order(tmp_path):
    database_path = tmp_path / "medishield.sqlite3"
    connection = initialize_db(database_path)
    connection.execute(
        "UPDATE orders SET dose = ? WHERE order_id = ?",
        ("7", "ORD-DEMO-001"),
    )
    connection.commit()
    connection.close()

    reopened = initialize_db(database_path)
    try:
        dose = reopened.execute(
            "SELECT dose FROM orders WHERE order_id = ?",
            ("ORD-DEMO-001",),
        ).fetchone()[0]
    finally:
        reopened.close()

    assert dose == "7"


def test_write_event_stores_database_and_matching_jsonl(isolated_database):
    database_path, log_path = isolated_database
    event = {
        "time": "2026-10-14T08:00:00Z",
        "request_id": "REQ-TEST-001",
        "actor": "agent_1",
        "tool": "update_order",
        "action_type": "update_order",
        "approval_id": "APR-TEST-001",
        "decision": "allowed",
        "risk": "medium",
        "rule": "intent hash matched",
        "reason": "Synthetic test event.",
        "changed_fields": [],
        "state_changed": True,
    }

    write_event(event)

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT time, request_id, actor_id, tool, action_type, approval_id,
                   decision, risk, rule, reason, changed_fields, state_changed
            FROM audit_events
            """
        ).fetchone()
    with log_path.open(encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle]

    assert len(records) == 1
    assert records[0] == event
    assert row[:10] == (
        event["time"],
        event["request_id"],
        event["actor"],
        event["tool"],
        event["action_type"],
        event["approval_id"],
        event["decision"],
        event["risk"],
        event["rule"],
        event["reason"],
    )
    assert json.loads(row[10]) == event["changed_fields"]
    assert bool(row[11]) is event["state_changed"]


def test_write_event_rolls_back_owned_database_on_file_failure(
    isolated_database, monkeypatch
):
    database_path, _ = isolated_database
    event = {
        "time": "2026-10-14T08:00:00Z",
        "request_id": "REQ-TEST-FAIL",
        "actor": "agent_1",
        "tool": "update_order",
        "action_type": "update_order",
        "approval_id": None,
        "decision": "blocked",
        "risk": "high",
        "rule": "test failure",
        "reason": "Synthetic failure-path test.",
        "changed_fields": ["dose"],
        "state_changed": False,
    }

    import guard.audit as audit

    def fail_append(*args, **kwargs):
        raise OSError("synthetic log failure")

    monkeypatch.setattr(audit, "_append_jsonl", fail_append)
    with pytest.raises(OSError):
        audit.write_event(event)

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0

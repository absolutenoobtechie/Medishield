"""Focused tests for backend approvals and audit persistence."""

import json
import sqlite3

import pytest

from guard.audit import write_event
from guard.intent import action_hash, canonicalize_action
from guard.models import ProtectedAction
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


def test_create_approval_stores_canonical_action_and_hash(isolated_database):
    database_path, _ = isolated_database
    action = make_action()

    approval_id = backend.create_approval(action, "clinician_1", 5)

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT action_json, action_hash, approver_id FROM approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
    assert row == (canonicalize_action(action), action_hash(action), "clinician_1")


@pytest.mark.parametrize("approver_id", ["missing_actor", "nurse_1", "agent_1"])
def test_create_approval_rejects_non_clinician_or_missing_actor(
    isolated_database, approver_id
):
    with pytest.raises((LookupError, PermissionError, ValueError)):
        backend.create_approval(make_action(), approver_id, 5)


@pytest.mark.parametrize("ttl_minutes", [0, -1, "not-a-number"])
def test_create_approval_rejects_non_positive_ttl(isolated_database, ttl_minutes):
    with pytest.raises(ValueError):
        backend.create_approval(make_action(), "clinician_1", ttl_minutes)


def test_revoke_approval_marks_existing_row_and_rejects_unknown(isolated_database):
    database_path, _ = isolated_database
    approval_id = backend.create_approval(make_action(), "clinician_1", 5)

    backend.revoke_approval(approval_id)
    with sqlite3.connect(database_path) as connection:
        revoked = connection.execute(
            "SELECT revoked FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()[0]
    assert revoked == 1

    with pytest.raises(LookupError):
        backend.revoke_approval("APR-UNKNOWN")


def test_apply_order_uses_caller_transaction(isolated_database):
    database_path, _ = isolated_database
    connection = initialize_db(database_path)
    action = make_action("ORD-TEST-002")

    backend.apply_order(action, connection=connection)
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

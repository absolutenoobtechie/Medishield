"""Focused tests for audit trail integrity protection and tamper detection."""

import copy
import json
import sqlite3
import pytest

from guard.audit import (
    compute_audit_chain_hash,
    compute_event_digest,
    verify_audit_log_integrity,
    write_event,
)
from guard.forensics import verify_audit_integrity
from server.db import init_db


@pytest.fixture
def sample_events():
    return [
        {
            "time": "2026-10-14T08:00:00Z",
            "request_id": "REQ-AUDIT-001",
            "actor": "agent_1",
            "tool": "get_patient_record",
            "action_type": "get_patient_record",
            "approval_id": None,
            "decision": "allowed",
            "risk": "low",
            "rule": "patient read allowed",
            "reason": "Synthetic patient read.",
            "changed_fields": [],
            "state_changed": False,
        },
        {
            "time": "2026-10-14T08:05:00Z",
            "request_id": "REQ-AUDIT-002",
            "actor": "agent_1",
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": "APR-001",
            "decision": "blocked",
            "risk": "high",
            "rule": "intent hash mismatch",
            "reason": "Dose tampered from 5 to 50.",
            "changed_fields": ["dose"],
            "state_changed": False,
        },
        {
            "time": "2026-10-14T08:10:00Z",
            "request_id": "REQ-AUDIT-003",
            "actor": "agent_1",
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": "APR-002",
            "decision": "allowed",
            "risk": "medium",
            "rule": "intent hash matched",
            "reason": "Executed valid approved order.",
            "changed_fields": [],
            "state_changed": True,
        },
    ]


def test_intact_audit_events_pass_integrity_check(sample_events):
    chain_digest = compute_audit_chain_hash(sample_events)
    result = verify_audit_log_integrity(
        records=sample_events,
        expected_chain_digest=chain_digest,
    )

    assert result["valid"] is True
    assert result["tampering_detected"] is False
    assert result["tampering_type"] is None
    assert result["record_count"] == 3
    assert result["chain_digest"] == chain_digest
    assert result["errors"] == []


def test_modified_event_is_detected(sample_events):
    tampered_events = copy.deepcopy(sample_events)
    # Attacker tries to alter "blocked" to "allowed" in event #2
    tampered_events[1]["decision"] = "allowed"
    original_chain_digest = compute_audit_chain_hash(sample_events)

    result = verify_audit_log_integrity(
        records=tampered_events,
        expected_chain_digest=original_chain_digest,
    )

    assert result["valid"] is False
    assert result["tampering_detected"] is True
    assert result["tampering_type"] == "modification"
    assert any("Chain digest mismatch" in err for err in result["errors"])


def test_reordered_events_are_detected(sample_events):
    # Swap event 1 (08:05:00Z) and event 2 (08:10:00Z) with event 0 (08:00:00Z)
    reordered_events = [sample_events[1], sample_events[0], sample_events[2]]

    result = verify_audit_log_integrity(records=reordered_events)

    assert result["valid"] is False
    assert result["tampering_detected"] is True
    assert result["tampering_type"] == "reordering"
    assert any("reordering detected" in err for err in result["errors"])


def test_deleted_event_is_detected_in_sqlite(tmp_path, sample_events):
    db_path = tmp_path / "test_audit.sqlite3"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    init_db(conn)

    log_path = tmp_path / "events.jsonl"

    for event in sample_events:
        write_event(event, connection=conn, log_path=log_path)
    conn.commit()

    # Verify initially valid
    initial_check = verify_audit_log_integrity(
        log_path=log_path,
        connection=conn,
    )
    assert initial_check["valid"] is True
    assert initial_check["cross_store_verified"] is True
    assert initial_check["record_count"] == 3

    # Attacker deletes event row id=2 from SQLite
    conn.execute("DELETE FROM audit_events WHERE id = 2")
    conn.commit()

    tampered_check = verify_audit_log_integrity(
        log_path=log_path,
        connection=conn,
    )
    assert tampered_check["valid"] is False
    assert tampered_check["tampering_detected"] is True
    assert tampered_check["tampering_type"] == "deletion"
    assert any("deletion detected" in err for err in tampered_check["errors"])
    conn.close()


def test_cross_store_content_mismatch_is_detected(tmp_path, sample_events):
    db_path = tmp_path / "test_audit.sqlite3"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    init_db(conn)

    log_path = tmp_path / "events.jsonl"

    for event in sample_events:
        write_event(event, connection=conn, log_path=log_path)
    conn.commit()

    # Attacker stealthily modifies SQLite reason without updating JSONL
    conn.execute("UPDATE audit_events SET reason = 'Tampered reason' WHERE id = 1")
    conn.commit()

    result = verify_audit_integrity(log_path=log_path, connection=conn)

    assert result["valid"] is False
    assert result["tampering_detected"] is True
    assert result["tampering_type"] == "modification"
    assert any("Cross-store mismatch" in err for err in result["errors"])
    conn.close()


def test_missing_jsonl_store_is_not_reported_as_intact(tmp_path, sample_events):
    db_path = tmp_path / "test_audit.sqlite3"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    log_path = tmp_path / "missing-events.jsonl"

    for event in sample_events:
        write_event(event, connection=conn, log_path=tmp_path / "events.jsonl")
    conn.commit()

    result = verify_audit_log_integrity(log_path=log_path, connection=conn)

    assert result["valid"] is False
    assert result["tampering_detected"] is True
    assert any("missing" in error.lower() for error in result["errors"])
    conn.close()

"""Integration tests for MediShield gateway security enforcement."""

import json
import sqlite3
import pytest

from guard.gateway import verify_execution
from guard.intent import action_hash
from guard.models import ExecutionRequest, ProtectedAction
from server.db import init_db, seed_data


from guard.policy import PINNED_DESTINATIONS

DESTINATION = PINNED_DESTINATIONS["update_order"]


@pytest.fixture
def test_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    seed_data(conn)
    yield conn
    conn.close()


def create_approval(conn, approval_id, action_dict, approver_id="clinician_1"):
    action_obj = ProtectedAction(**action_dict)
    h = action_hash(action_obj)
    conn.execute(
        """
        INSERT INTO approvals (approval_id, action_hash, action_json, approver_id, created_at, expires_at, revoked, consumed)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            approval_id,
            h,
            json.dumps(action_dict),
            approver_id,
            "2026-10-14T00:00:00Z",
            "2026-10-15T00:00:00Z",
            0,
            0,
        ),
    )
    conn.commit()
    return h


def test_valid_approved_action_succeeds(test_db):
    action_dict = {
        "order_id": "ORD-DEMO-001",
        "patient_id": "P-104",
        "medication_id": "MED-A",
        "dose": "5",
        "units": "mg",
        "route": "oral",
        "frequency": "daily",
        "duration": "7 days",
    }
    create_approval(test_db, "APR-TEST-01", action_dict)

    req = ExecutionRequest(
        request_id="REQ-TEST-01",
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-TEST-01",
        action=ProtectedAction(**action_dict),
        destination=DESTINATION,
    )

    decision = verify_execution(req, test_db, destination=DESTINATION)
    assert decision.decision == "allowed"
    assert decision.state_changed is True
    assert decision.rule == "intent hash matched"

    # Verify DB order state was updated
    order = test_db.execute("SELECT * FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()
    assert order["dose"] == "5"

    # Verify approval was consumed
    app = test_db.execute("SELECT consumed FROM approvals WHERE approval_id = 'APR-TEST-01'").fetchone()
    assert app["consumed"] == 1


def test_tampered_dose_is_blocked(test_db):
    approved_dict = {
        "order_id": "ORD-DEMO-001",
        "patient_id": "P-104",
        "medication_id": "MED-A",
        "dose": "5",
        "units": "mg",
        "route": "oral",
        "frequency": "daily",
        "duration": "7 days",
    }
    create_approval(test_db, "APR-TEST-02", approved_dict)

    # Agent tampers dose from 5 to 50
    tampered_dict = dict(approved_dict, dose="50")
    req = ExecutionRequest(
        request_id="REQ-TEST-02",
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-TEST-02",
        action=ProtectedAction(**tampered_dict),
        destination=DESTINATION,
    )

    # Initial order dose before attack
    orig_order = test_db.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()

    decision = verify_execution(req, test_db, destination=DESTINATION)
    assert decision.decision == "blocked"
    assert decision.state_changed is False
    assert decision.rule == "intent hash mismatch"
    assert "dose" in decision.changed_fields

    # Ensure backend state unchanged!
    curr_order = test_db.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()
    assert curr_order["dose"] == orig_order["dose"]


def test_patient_substitution_is_blocked(test_db):
    approved_dict = {
        "order_id": "ORD-DEMO-001",
        "patient_id": "P-104",
        "medication_id": "MED-A",
        "dose": "5",
        "units": "mg",
        "route": "oral",
        "frequency": "daily",
        "duration": "7 days",
    }
    create_approval(test_db, "APR-TEST-03", approved_dict)

    # Agent substitutes patient to P-205
    substituted_dict = dict(approved_dict, patient_id="P-205")
    req = ExecutionRequest(
        request_id="REQ-TEST-03",
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-TEST-03",
        action=ProtectedAction(**substituted_dict),
        destination=DESTINATION,
    )

    decision = verify_execution(req, test_db, destination=DESTINATION)
    assert decision.decision == "blocked"
    assert decision.state_changed is False
    assert decision.rule == "intent hash mismatch"
    assert "patient_id" in decision.changed_fields


def test_approval_replay_is_rejected(test_db):
    action_dict = {
        "order_id": "ORD-DEMO-001",
        "patient_id": "P-104",
        "medication_id": "MED-A",
        "dose": "5",
        "units": "mg",
        "route": "oral",
        "frequency": "daily",
        "duration": "7 days",
    }
    create_approval(test_db, "APR-TEST-04", action_dict)

    req1 = ExecutionRequest(
        request_id="REQ-TEST-04A",
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-TEST-04",
        action=ProtectedAction(**action_dict),
        destination=DESTINATION,
    )
    # First execution succeeds
    dec1 = verify_execution(req1, test_db, destination=DESTINATION)
    assert dec1.decision == "allowed"

    # Replay execution fails
    req2 = ExecutionRequest(
        request_id="REQ-TEST-04B",
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-TEST-04",
        action=ProtectedAction(**action_dict),
        destination=DESTINATION,
    )
    dec2 = verify_execution(req2, test_db, destination=DESTINATION)
    assert dec2.decision == "blocked"
    assert dec2.rule == "approval already consumed"
    assert dec2.state_changed is False


def test_missing_destination_is_blocked(test_db):
    action_dict = {
        "order_id": "ORD-DEMO-001",
        "patient_id": "P-104",
        "medication_id": "MED-A",
        "dose": "5",
        "units": "mg",
        "route": "oral",
        "frequency": "daily",
        "duration": "7 days",
    }
    create_approval(test_db, "APR-TEST-DEST-01", action_dict)

    req = ExecutionRequest(
        request_id="REQ-TEST-NODEST",
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-TEST-DEST-01",
        action=ProtectedAction(**action_dict),
        destination=None,
    )

    orig_order = test_db.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()

    # Omit destination parameter as well
    decision = verify_execution(req, test_db, destination=None)
    assert decision.decision == "blocked"
    assert decision.rule == "destination not pinned"
    assert decision.state_changed is False

    # Backend state unchanged
    curr_order = test_db.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()
    assert curr_order["dose"] == orig_order["dose"]

    # Audit event is recorded
    event = test_db.execute(
        "SELECT decision, rule, state_changed FROM audit_events WHERE request_id = 'REQ-TEST-NODEST'"
    ).fetchone()
    assert event["decision"] == "blocked"
    assert event["rule"] == "destination not pinned"
    assert event["state_changed"] == 0


def test_incorrect_destination_is_blocked(test_db):
    action_dict = {
        "order_id": "ORD-DEMO-001",
        "patient_id": "P-104",
        "medication_id": "MED-A",
        "dose": "5",
        "units": "mg",
        "route": "oral",
        "frequency": "daily",
        "duration": "7 days",
    }
    create_approval(test_db, "APR-TEST-DEST-02", action_dict)

    req = ExecutionRequest(
        request_id="REQ-TEST-BADDEST",
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-TEST-DEST-02",
        action=ProtectedAction(**action_dict),
        destination="backend://unauthorized-destination/orders",
    )

    decision = verify_execution(req, test_db, destination="backend://unauthorized-destination/orders")
    assert decision.decision == "blocked"
    assert decision.rule == "destination not pinned"
    assert decision.state_changed is False

    event = test_db.execute(
        "SELECT decision, rule, state_changed FROM audit_events WHERE request_id = 'REQ-TEST-BADDEST'"
    ).fetchone()
    assert event["decision"] == "blocked"
    assert event["rule"] == "destination not pinned"
    assert event["state_changed"] == 0


@pytest.mark.parametrize(
    "bad_dose",
    [
        "0",
        "-5",
        "-0.1",
        "not-a-number",
        "1e999999999",
        "1" * 100,
        "1e100000",
        "NaN",
        "Infinity",
        "-Infinity",
    ],
)
def test_malformed_dose_fails_closed(test_db, bad_dose):
    action_dict = {
        "order_id": "ORD-DEMO-001",
        "patient_id": "P-104",
        "medication_id": "MED-A",
        "dose": "5",
        "units": "mg",
        "route": "oral",
        "frequency": "daily",
        "duration": "7 days",
    }
    create_approval(test_db, "APR-TEST-DOSE-01", action_dict)

    req_id = f"REQ-DOSE-{abs(hash(bad_dose)) % 1000000}"
    malformed_action = dict(action_dict, dose=bad_dose)

    req = ExecutionRequest(
        request_id=req_id,
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-TEST-DOSE-01",
        action=ProtectedAction(**malformed_action),
        destination=DESTINATION,
    )

    orig_order = test_db.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()

    # Must fail closed without uncaught exceptions
    decision = verify_execution(req, test_db, destination=DESTINATION)
    assert decision.decision == "blocked"
    assert decision.state_changed is False
    assert decision.rule == "malformed request"

    # Backend state unchanged
    curr_order = test_db.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()
    assert curr_order["dose"] == orig_order["dose"]

    # Audit event is recorded
    event = test_db.execute(
        "SELECT decision, rule, state_changed FROM audit_events WHERE request_id = ?",
        (req_id,),
    ).fetchone()
    assert event is not None
    assert event["decision"] == "blocked"
    assert event["rule"] == "malformed request"
    assert event["state_changed"] == 0


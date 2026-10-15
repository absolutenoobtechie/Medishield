"""Regression test suite for the MediShield verification workflow and setup_test_approval helper."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest

from dashboard.app import _setup_test_approval, setup_test_approval
from guard.gateway import verify_execution
from guard.intent import action_hash
from guard.models import ExecutionRequest, ProtectedAction
from guard.policy import PINNED_DESTINATIONS
from server.db import init_db, seed_data


@pytest.fixture
def test_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    seed_data(conn)
    yield conn
    conn.close()


def test_setup_test_approval_is_defined_at_module_level():
    """Regression test: verify _setup_test_approval is defined at module scope and callable."""
    assert callable(_setup_test_approval), "_setup_test_approval must be callable at module scope"
    assert callable(setup_test_approval), "setup_test_approval must be callable at module scope"
    assert _setup_test_approval is setup_test_approval


def test_setup_test_approval_persists_valid_record(test_db):
    """Verify setup_test_approval correctly hashes and inserts approval record into SQLite."""
    action_data = {
        "order_id": "ORD-DEMO-001",
        "patient_id": "P-104",
        "medication_id": "MED-A",
        "dose": "5",
        "units": "mg",
        "route": "oral",
        "frequency": "daily",
        "duration": "7 days",
    }
    app_id = "APR-TEST-REGRESSION-01"
    h = _setup_test_approval(test_db, app_id, action_data)

    assert isinstance(h, str)
    assert len(h) == 64

    # Verify database persistence
    row = test_db.execute(
        "SELECT * FROM approvals WHERE approval_id = ?", (app_id,)
    ).fetchone()
    assert row is not None
    assert row["action_hash"] == h
    assert row["approver_id"] == "clinician_1"
    assert row["revoked"] == 0
    assert row["consumed"] == 0


def test_verification_duration_mismatch_blocked(test_db):
    """Regression test for the screenshot scenario: approved 7 days vs submitted 8 days."""
    approved_action = {
        "order_id": "ORD-DEMO-001",
        "patient_id": "P-104",
        "medication_id": "MED-A",
        "dose": "5",
        "units": "mg",
        "route": "oral",
        "frequency": "daily",
        "duration": "7 days",
    }
    # Tampered duration
    submitted_action = dict(approved_action, duration="8 days")

    ts = int(datetime.now().timestamp() * 1000)
    app_id = f"APR-ACTION-VERIF-{ts}"

    # Setup approval via the resolved helper
    h = _setup_test_approval(test_db, app_id, approved_action)
    assert h == action_hash(ProtectedAction(**approved_action))

    # Dispatch verification request through the actual gateway
    req = ExecutionRequest(
        request_id=f"REQ-ACTION-VERIF-{ts}",
        actor_id="agent_1",
        tool="update_order",
        approval_id=app_id,
        action=ProtectedAction(**submitted_action),
        destination=PINNED_DESTINATIONS["update_order"],
    )
    decision = verify_execution(req, test_db)

    # Validate fail-closed security decision
    assert decision.decision == "blocked"
    assert decision.rule == "intent hash mismatch"
    assert decision.state_changed is False
    assert "duration" in decision.changed_fields


def test_verification_exact_match_allowed(test_db):
    """Verify that exact match produces allowed verdict with state modified."""
    action_data = {
        "order_id": "ORD-DEMO-001",
        "patient_id": "P-104",
        "medication_id": "MED-A",
        "dose": "5",
        "units": "mg",
        "route": "oral",
        "frequency": "daily",
        "duration": "7 days",
    }
    ts = int(datetime.now().timestamp() * 1000)
    app_id = f"APR-ACTION-EXACT-{ts}"

    _setup_test_approval(test_db, app_id, action_data)

    req = ExecutionRequest(
        request_id=f"REQ-ACTION-EXACT-{ts}",
        actor_id="agent_1",
        tool="update_order",
        approval_id=app_id,
        action=ProtectedAction(**action_data),
        destination=PINNED_DESTINATIONS["update_order"],
    )
    decision = verify_execution(req, test_db)

    assert decision.decision == "allowed"
    assert decision.rule == "intent hash matched"
    assert decision.state_changed is True
    assert len(decision.changed_fields) == 0

"""Automated verification suite for the MediShield monitored calls refresh counter.

Tests adherence to the exact 9-step refresh verification sequence:
1. Record initial count N of monitored calls.
2. Trigger a real or simulated tool call through the gateway.
3. Verify the call executes and produces a new monitoring record.
4. Trigger the refresh logic (or simulate what the Refresh button does).
5. Confirm the monitored calls counter is now N + 1.
6. Confirm the newest event corresponds to the call just executed.
7. Refresh again without executing another action; confirm count remains N + 1.
8. Trigger an invalid or blocked tool call; confirm counter is N + 2 and Blocked increments.
9. Verify that backend state remains unchanged when an action is blocked.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys

# Ensure repository root is on sys.path for direct pytest invocation
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest

from dashboard.app import load_events
from guard.gateway import verify_execution
from guard.intent import action_hash
from guard.models import ExecutionRequest, ProtectedAction
from server.db import DEFAULT_DB_PATH, get_connection, init_db, seed_data


def _register_test_approval(
    conn: sqlite3.Connection,
    approval_id: str,
    action_data: dict,
    approver_id: str = "clinician_1",
) -> str:
    """Helper to persist a valid clinician approval in the database."""
    prot = ProtectedAction(**action_data)
    h = action_hash(prot)
    conn.execute(
        """
        INSERT INTO approvals (approval_id, action_hash, action_json, approver_id, created_at, expires_at, revoked, consumed)
        VALUES (?, ?, ?, ?, ?, ?, 0, 0)
        ON CONFLICT(approval_id) DO UPDATE SET
            action_hash = excluded.action_hash,
            action_json = excluded.action_json,
            revoked = 0,
            consumed = 0
        """,
        (
            approval_id,
            h,
            json.dumps(action_data),
            approver_id,
            datetime.now(timezone.utc).isoformat(),
            "2026-12-31T23:59:59Z",
        ),
    )
    conn.commit()
    return h


def test_monitored_calls_refresh_counter_9_step_sequence():
    """Verify the complete 9-step sequence for the monitored calls refresh counter."""

    try:
        # --------------------------------------------------------------------------
        # Step 1: Record initial count N of monitored calls
        # --------------------------------------------------------------------------
        initial_events, _ = load_events()
        N = len(initial_events)
        initial_allowed = sum(1 for e in initial_events if str(e.get("decision")).lower() == "allowed")
        initial_blocked = sum(1 for e in initial_events if str(e.get("decision")).lower() == "blocked")
        assert N >= 0, "Initial event count must be non-negative"

        # --------------------------------------------------------------------------
        # Step 2: Trigger a real tool call through the gateway (valid approved write)
        # --------------------------------------------------------------------------
        ts1 = int(datetime.now().timestamp() * 1000)
        app1_id = f"APR-TEST-REFRESH-VAL-{ts1}"
        req1_id = f"REQ-TEST-REFRESH-VAL-{ts1}"
        valid_action_data = {
            "order_id": f"ORD-REF-VAL-{ts1}",
            "patient_id": "P-101",
            "medication_id": "MED-MET-500",
            "dose": "500",
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "30 days",
        }

        conn = get_connection(DEFAULT_DB_PATH)
        _register_test_approval(conn, app1_id, valid_action_data)

        valid_request = ExecutionRequest(
            request_id=req1_id,
            actor_id="agent_1",
            tool="update_order",
            approval_id=app1_id,
            action=ProtectedAction(**valid_action_data),
        )
        decision1 = verify_execution(valid_request, conn)
        conn.close()

        assert decision1.decision == "allowed"
        assert decision1.rule == "intent hash matched"
        assert decision1.state_changed is True

        # --------------------------------------------------------------------------
        # Step 3: Verify the call executes and produces a new monitoring record
        # --------------------------------------------------------------------------
        conn = get_connection(DEFAULT_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_events WHERE request_id = ?", (req1_id,))
        row1 = cur.fetchone()
        assert row1 is not None, f"Audit event for {req1_id} must exist in audit_events table"
        assert row1["decision"] == "allowed"
        assert row1["state_changed"] == 1

        # Verify backend order was genuinely updated
        cur.execute("SELECT * FROM orders WHERE order_id = ?", (valid_action_data["order_id"],))
        order1 = cur.fetchone()
        assert order1 is not None, "Order must exist in backend database"
        assert order1["dose"] == "500"
        conn.close()

        # --------------------------------------------------------------------------
        # Step 4: Trigger the refresh logic (simulate what the Refresh button does)
        # --------------------------------------------------------------------------
        refreshed_events, active_source = load_events()

        # --------------------------------------------------------------------------
        # Step 5: Confirm the monitored calls counter is now N + 1
        # --------------------------------------------------------------------------
        assert len(refreshed_events) == N + 1, f"Counter should increment to {N + 1}, got {len(refreshed_events)}"
        new_allowed = sum(1 for e in refreshed_events if str(e.get("decision")).lower() == "allowed")
        assert new_allowed == initial_allowed + 1, "Allowed calls counter must increment by 1"

        # --------------------------------------------------------------------------
        # Step 6: Confirm the newest event corresponds to the call just executed
        # --------------------------------------------------------------------------
        newest_event = refreshed_events[0]
        assert newest_event["request_id"] == req1_id, f"Newest event must be {req1_id}, got {newest_event['request_id']}"
        assert newest_event["decision"] == "allowed"
        assert newest_event["tool"] == "update_order"

        # --------------------------------------------------------------------------
        # Step 7: Refresh again without executing another action; confirm count is N + 1
        # --------------------------------------------------------------------------
        refreshed_again, _ = load_events()
        assert len(refreshed_again) == N + 1, "Second refresh without new actions must keep count at N + 1"
        assert sum(1 for e in refreshed_again if str(e.get("decision")).lower() == "allowed") == initial_allowed + 1
        assert refreshed_again[0]["request_id"] == req1_id, "Newest event must remain req1 after subsequent refresh"

        # --------------------------------------------------------------------------
        # Step 8: Trigger an invalid or blocked tool call; confirm counter is N + 2
        # --------------------------------------------------------------------------
        ts2 = int(datetime.now().timestamp() * 1000) + 1
        app2_id = f"APR-TEST-REFRESH-ATK-{ts2}"
        req2_id = f"REQ-TEST-REFRESH-ATK-{ts2}"
        approved_action2 = {
            "order_id": f"ORD-REF-ATK-{ts2}",
            "patient_id": "P-102",
            "medication_id": "MED-INS-GLA",
            "dose": "5",
            "units": "units",
            "route": "subcutaneous",
            "frequency": "daily",
            "duration": "ongoing",
        }
        tampered_action2 = dict(approved_action2)
        tampered_action2["dose"] = "50"  # 10x unauthorized dose tampering

        conn = get_connection(DEFAULT_DB_PATH)
        _register_test_approval(conn, app2_id, approved_action2)

        blocked_request = ExecutionRequest(
            request_id=req2_id,
            actor_id="agent_1",
            tool="update_order",
            approval_id=app2_id,
            action=ProtectedAction(**tampered_action2),
        )
        decision2 = verify_execution(blocked_request, conn)
        conn.close()

        assert decision2.decision == "blocked"
        assert decision2.rule == "intent hash mismatch"
        assert decision2.state_changed is False
        assert "dose" in decision2.changed_fields

        # Trigger refresh after blocked call
        refreshed_after_blocked, _ = load_events()
        assert len(refreshed_after_blocked) == N + 2, f"Counter should increment to {N + 2}, got {len(refreshed_after_blocked)}"
        new_blocked = sum(1 for e in refreshed_after_blocked if str(e.get("decision")).lower() == "blocked")
        assert new_blocked == initial_blocked + 1, "Blocked calls counter must increment by 1"
        assert refreshed_after_blocked[0]["request_id"] == req2_id, f"Newest event must be blocked call {req2_id}"

        # --------------------------------------------------------------------------
        # Step 9: Verify that backend state remains unchanged when an action is blocked
        # --------------------------------------------------------------------------
        conn = get_connection(DEFAULT_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT * FROM orders WHERE order_id = ?", (approved_action2["order_id"],))
        blocked_order = cur.fetchone()
        if blocked_order is not None:
            assert blocked_order["dose"] != "50", "Blocked tampered dose must NOT be written to backend"
        conn.close()
    finally:
        # Clean up test rows to keep the persistent database clean
        try:
            cleanup_conn = get_connection(DEFAULT_DB_PATH)
            cleanup_conn.execute("DELETE FROM audit_events WHERE request_id LIKE 'REQ-TEST-REFRESH-%'")
            cleanup_conn.execute("DELETE FROM approvals WHERE approval_id LIKE 'APR-TEST-REFRESH-%'")
            cleanup_conn.execute("DELETE FROM orders WHERE order_id LIKE 'ORD-REF-%'")
            cleanup_conn.commit()
            cleanup_conn.close()
        except Exception:
            pass


def test_refresh_preserves_newest_first_order():
    """Verify that load_events strictly returns records with the latest first."""
    events, _ = load_events()
    assert len(events) >= 2
    for i in range(len(events) - 1):
        t1 = str(events[i].get("time") or "")
        t2 = str(events[i + 1].get("time") or "")
        assert t1 >= t2 or (t1 == t2 and events[i].get("id", 0) >= events[i + 1].get("id", 0)), (
            f"Ordering violation at index {i}: {t1} vs {t2}"
        )

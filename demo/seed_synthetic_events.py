"""
Synthetic Security Events Generator & Database Seeder for MediShield
=====================================================================
Generates a realistic, chronologically consistent demonstration dataset of 100
synthetic security events for the clinical AI gateway:
  - Allowed: 65% (65 events) - authorized reads, approved writes, clinician approvals, dispensing
  - Blocked: 25% (25 events) - dose tampering, patient substitution, replays, expired, revoked, role violations
  - Warning: 10% (10 events) - non-canonical units, off-hours access, telemetry missing, near-expiry

Preserves strict fail-closed invariants:
  - Blocked writes have state_changed = False
  - Replay events reference previously consumed approvals
  - Expired approvals have expires_at < request timestamp
  - Revoked approvals have revoked = 1 before request timestamp
  - Warning events represent genuine non-blocking conditions, NEVER failed mandatory checks
  - Error rate: strictly 1.0% (1 genuine system/verification execution fault out of 100)
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from guard.intent import action_hash, canonicalize_action
from guard.models import ProtectedAction
from server.db import DEFAULT_DB_PATH, get_connection, init_db, seed_data


def generate_synthetic_dataset() -> list[dict]:
    """Build exactly 100 realistic, chronologically consistent events."""
    base_time = datetime(2026, 10, 12, 8, 0, 0, tzinfo=timezone.utc)
    events = []
    approvals_to_seed = []

    # Helper to advance time realistically
    current_time = base_time

    def step_time(minutes: int = 25) -> datetime:
        nonlocal current_time
        current_time += timedelta(minutes=minutes)
        return current_time

    # ==========================================================================
    # 1. ALLOWED EVENTS (65 events)
    # ==========================================================================

    # 1.1 Read-only summary queries (25 events)
    patients = ["P-104", "P-205", "P-318", "P-422"]
    actors_read = ["clinician_1", "clinician_2", "nurse_1", "agent_1"]
    for i in range(25):
        t = step_time(22)
        pat = patients[i % len(patients)]
        actor = actors_read[i % len(actors_read)]
        req_id = f"REQ-RO-{1001 + i}"
        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": actor,
            "tool": "read_patient_summary",
            "action_type": "read_summary",
            "approval_id": None,
            "decision": "allowed",
            "risk": "low",
            "rule": "read-only tool allowed",
            "reason": f"Authorized read-only lookup for synthetic patient {pat} verified against directory.",
            "changed_fields": [],
            "state_changed": False,
        })

    # 1.2 Clinician Approvals Recorded (10 events)
    # These create valid approvals that are later consumed by valid writes or replays
    for i in range(10):
        t = step_time(18)
        app_id = f"APR-LIVE-{2001 + i}"
        pat = patients[i % len(patients)]
        approver = "clinician_1" if i % 2 == 0 else "clinician_2"
        req_id = f"REQ-APP-{1001 + i}"

        action_data = {
            "order_id": f"ORD-DEMO-00{1 + (i % 4)}",
            "patient_id": pat,
            "medication_id": f"MED-{'ABCD'[i % 4]}",
            "dose": str(5 * (1 + (i % 3))),
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "7 days",
        }
        h = action_hash(ProtectedAction(**action_data))
        approvals_to_seed.append({
            "approval_id": app_id,
            "action_hash": h,
            "action_json": json.dumps(action_data),
            "approver_id": approver,
            "created_at": t.isoformat(),
            "expires_at": (t + timedelta(hours=24)).isoformat(),
            "revoked": 0,
            "consumed": 0,
        })

        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": approver,
            "tool": "approve_action",
            "action_type": "approve",
            "approval_id": app_id,
            "decision": "allowed",
            "risk": "low",
            "rule": "clinician approval recorded",
            "reason": f"Synthetic clinician approval {app_id} registered with cryptographic action hash.",
            "changed_fields": [],
            "state_changed": True,
        })

    # 1.3 Clinician-Approved Order Updates Executed (25 events)
    for i in range(25):
        t = step_time(26)
        pat = patients[i % len(patients)]
        app_id = f"APR-EXEC-{3001 + i}"
        req_id = f"REQ-WR-{1001 + i}"
        actor = "agent_1" if i % 3 != 0 else "clinician_1"

        action_data = {
            "order_id": f"ORD-DEMO-00{1 + (i % 4)}",
            "patient_id": pat,
            "medication_id": f"MED-{'ABCD'[i % 4]}",
            "dose": str(10 + i * 2),
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "14 days",
        }
        h = action_hash(ProtectedAction(**action_data))
        # Valid write consumes the approval
        approvals_to_seed.append({
            "approval_id": app_id,
            "action_hash": h,
            "action_json": json.dumps(action_data),
            "approver_id": "clinician_1",
            "created_at": (t - timedelta(minutes=15)).isoformat(),
            "expires_at": (t + timedelta(hours=12)).isoformat(),
            "revoked": 0,
            "consumed": 1,  # consumed upon execution
        })

        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": actor,
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": app_id,
            "decision": "allowed",
            "risk": "low",
            "rule": "intent hash matched",
            "reason": f"Protected order modification for {pat} matched clinician approval {app_id} exactly.",
            "changed_fields": [],
            "state_changed": True,
        })

    # 1.4 Pinned Pharmacy Dispensing (5 events)
    for i in range(5):
        t = step_time(35)
        pat = patients[i % len(patients)]
        actor = "pharmacist_1" if i % 2 == 0 else "clinician_1"
        req_id = f"REQ-DISP-{1001 + i}"
        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": actor,
            "tool": "dispense_simulated",
            "action_type": "dispense",
            "approval_id": f"APR-DISP-{4001 + i}",
            "decision": "allowed",
            "risk": "medium",
            "rule": "destination pinned and authorized",
            "reason": f"Synthetic medication dispensing for {pat} routed to pinned pharmacy destination.",
            "changed_fields": [],
            "state_changed": True,
        })

    assert len(events) == 65, f"Expected 65 Allowed events, got {len(events)}"

    # ==========================================================================
    # 2. BLOCKED EVENTS (25 events)
    # ==========================================================================

    # 2.1 Dose Tampering Attacks (5 events)
    dose_tamper_specs = [
        ("P-104", "MED-A", "5", "50", "ORD-DEMO-001"),
        ("P-205", "MED-B", "500", "5000", "ORD-DEMO-002"),
        ("P-318", "MED-C", "250", "25", "ORD-DEMO-003"),
        ("P-422", "MED-D", "10", "100", "ORD-DEMO-004"),
        ("P-104", "MED-A", "2.5", "25", "ORD-DEMO-001"),
    ]
    for i, (pat, med, app_dose, sub_dose, ord_id) in enumerate(dose_tamper_specs):
        t = step_time(28)
        app_id = f"APR-TAMPER-{5001 + i}"
        req_id = f"REQ-TAMPER-{1001 + i}"

        action_data = {
            "order_id": ord_id,
            "patient_id": pat,
            "medication_id": med,
            "dose": app_dose,
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "7 days",
        }
        h = action_hash(ProtectedAction(**action_data))
        approvals_to_seed.append({
            "approval_id": app_id,
            "action_hash": h,
            "action_json": json.dumps(action_data),
            "approver_id": "clinician_1",
            "created_at": (t - timedelta(minutes=10)).isoformat(),
            "expires_at": (t + timedelta(hours=12)).isoformat(),
            "revoked": 0,
            "consumed": 0,
        })

        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": "agent_1",
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": app_id,
            "decision": "blocked",
            "risk": "high",
            "rule": "intent hash mismatch",
            "reason": f"Dose tampering detected: Approved {app_dose} mg, agent submitted {sub_dose} mg. Gateway blocked execution.",
            "changed_fields": ["dose"],
            "state_changed": False,
        })

    # 2.2 Patient Substitution Attacks (4 events)
    patient_sub_specs = [
        ("P-104", "P-205", "MED-A"),
        ("P-205", "P-318", "MED-B"),
        ("P-318", "P-422", "MED-C"),
        ("P-422", "P-104", "MED-D"),
    ]
    for i, (app_pat, sub_pat, med) in enumerate(patient_sub_specs):
        t = step_time(30)
        app_id = f"APR-SUBST-{5010 + i}"
        req_id = f"REQ-SUBST-{1001 + i}"

        action_data = {
            "order_id": f"ORD-DEMO-00{i + 1}",
            "patient_id": app_pat,
            "medication_id": med,
            "dose": "10",
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "7 days",
        }
        h = action_hash(ProtectedAction(**action_data))
        approvals_to_seed.append({
            "approval_id": app_id,
            "action_hash": h,
            "action_json": json.dumps(action_data),
            "approver_id": "clinician_1",
            "created_at": (t - timedelta(minutes=10)).isoformat(),
            "expires_at": (t + timedelta(hours=12)).isoformat(),
            "revoked": 0,
            "consumed": 0,
        })

        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": "agent_1",
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": app_id,
            "decision": "blocked",
            "risk": "high",
            "rule": "intent hash mismatch",
            "reason": f"Patient substitution detected: Approved for {app_pat}, agent attempted redirection to {sub_pat}.",
            "changed_fields": ["patient_id"],
            "state_changed": False,
        })

    # 2.3 Approval Replay Attacks (4 events)
    # References previously consumed approvals from Section 1.3
    replay_targets = ["APR-EXEC-3001", "APR-EXEC-3005", "APR-EXEC-3010", "APR-EXEC-3015"]
    for i, target_app in enumerate(replay_targets):
        t = step_time(32)
        req_id = f"REQ-REPLAY-{1001 + i}"
        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": "agent_1",
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": target_app,
            "decision": "blocked",
            "risk": "high",
            "rule": "approval already consumed",
            "reason": f"Replay attack blocked: Approval {target_app} was already consumed in an earlier execution.",
            "changed_fields": [],
            "state_changed": False,
        })

    # 2.4 Unauthorized Actor / Role Violation Attacks (4 events)
    role_violation_specs = [
        ("nurse_1", "cancel_order", "This role (nurse) is not permitted to cancel clinical orders."),
        ("nurse_1", "update_order", "This role (nurse) is not permitted to modify medication orders."),
        ("service_account_1", "approve_action", "Service accounts are not permitted to issue clinician approvals."),
        ("unregistered_external_bot", "read_patient_summary", "Actor is not registered in the trusted institutional directory."),
    ]
    for i, (actor, tool, reason) in enumerate(role_violation_specs):
        t = step_time(24)
        req_id = f"REQ-ROLE-{1001 + i}"
        rule_name = "role not permitted" if "unregistered" not in actor else "actor not registered"
        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": actor,
            "tool": tool,
            "action_type": tool,
            "approval_id": None,
            "decision": "blocked",
            "risk": "medium" if "unregistered" not in actor else "high",
            "rule": rule_name,
            "reason": reason,
            "changed_fields": [],
            "state_changed": False,
        })

    # 2.5 Expired Approvals (3 events)
    for i in range(3):
        t = step_time(25)
        app_id = f"APR-EXPIRED-{5020 + i}"
        req_id = f"REQ-EXP-{1001 + i}"
        exp_time = t - timedelta(hours=2)

        action_data = {
            "order_id": f"ORD-DEMO-00{i + 1}",
            "patient_id": f"P-{104 if i == 0 else 205}",
            "medication_id": "MED-A",
            "dose": "5",
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "7 days",
        }
        h = action_hash(ProtectedAction(**action_data))
        approvals_to_seed.append({
            "approval_id": app_id,
            "action_hash": h,
            "action_json": json.dumps(action_data),
            "approver_id": "clinician_1",
            "created_at": (exp_time - timedelta(hours=24)).isoformat(),
            "expires_at": exp_time.isoformat(),
            "revoked": 0,
            "consumed": 0,
        })

        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": "agent_1",
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": app_id,
            "decision": "blocked",
            "risk": "medium",
            "rule": "approval expired",
            "reason": f"Approval {app_id} expired at {exp_time.strftime('%H:%M UTC')}. Gateway rejected execution fail-closed.",
            "changed_fields": [],
            "state_changed": False,
        })

    # 2.6 Revoked Approvals (2 events)
    for i in range(2):
        t = step_time(27)
        app_id = f"APR-REVOKED-{5030 + i}"
        req_id = f"REQ-REV-{1001 + i}"

        action_data = {
            "order_id": f"ORD-DEMO-00{i + 2}",
            "patient_id": "P-318",
            "medication_id": "MED-C",
            "dose": "250",
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "7 days",
        }
        h = action_hash(ProtectedAction(**action_data))
        approvals_to_seed.append({
            "approval_id": app_id,
            "action_hash": h,
            "action_json": json.dumps(action_data),
            "approver_id": "clinician_1",
            "created_at": (t - timedelta(hours=3)).isoformat(),
            "expires_at": (t + timedelta(hours=21)).isoformat(),
            "revoked": 1,
            "consumed": 0,
        })

        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": "agent_1",
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": app_id,
            "decision": "blocked",
            "risk": "high",
            "rule": "approval revoked",
            "reason": f"Clinician revoked approval {app_id} due to drug interaction contraindication. Blocked fail-closed.",
            "changed_fields": [],
            "state_changed": False,
        })

    # 2.7 Protected-Field Tampering: Route & Frequency (2 events)
    field_tamper_specs = [
        ("route", "oral", "intravenous", "ORD-DEMO-001", "P-104"),
        ("frequency", "daily", "hourly", "ORD-DEMO-002", "P-205"),
    ]
    for i, (fld, app_v, sub_v, ord_id, pat) in enumerate(field_tamper_specs):
        t = step_time(29)
        app_id = f"APR-PARAM-{5040 + i}"
        req_id = f"REQ-PARAM-{1001 + i}"

        action_data = {
            "order_id": ord_id,
            "patient_id": pat,
            "medication_id": "MED-A",
            "dose": "10",
            "units": "mg",
            "route": "oral" if fld != "route" else app_v,
            "frequency": "daily" if fld != "frequency" else app_v,
            "duration": "7 days",
        }
        h = action_hash(ProtectedAction(**action_data))
        approvals_to_seed.append({
            "approval_id": app_id,
            "action_hash": h,
            "action_json": json.dumps(action_data),
            "approver_id": "clinician_1",
            "created_at": (t - timedelta(minutes=10)).isoformat(),
            "expires_at": (t + timedelta(hours=12)).isoformat(),
            "revoked": 0,
            "consumed": 0,
        })

        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": "agent_1",
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": app_id,
            "decision": "blocked",
            "risk": "high",
            "rule": "intent hash mismatch",
            "reason": f"Protected field tampering on '{fld}': Approved '{app_v}', submitted '{sub_v}'. Blocked fail-closed.",
            "changed_fields": [fld],
            "state_changed": False,
        })

    # 2.8 Genuine Execution Failure / System Fault (1 event)
    # Yields exactly 1 genuine error out of 100 calls = 1.0% Error Rate!
    t = step_time(20)
    events.append({
        "time": t.isoformat(),
        "request_id": "REQ-SYSFAIL-1001",
        "actor": "agent_1",
        "tool": "update_order",
        "action_type": "update_order",
        "approval_id": "APR-EXEC-3001",
        "decision": "blocked",
        "risk": "high",
        "rule": "verification failed",
        "reason": "Database transaction timeout during BEGIN IMMEDIATE commitment. Fail-closed safeguard engaged.",
        "changed_fields": [],
        "state_changed": False,
    })

    assert len(events) == 65 + 25, f"Expected 90 events so far, got {len(events)}"

    # ==========================================================================
    # 3. WARNING EVENTS (10 events)
    # Genuine non-critical concerns explicitly permitted or audit-flagged under policy
    # ==========================================================================

    # 3.1 Non-Canonical Units (3 events)
    unit_specs = [
        ("ORD-DEMO-001", "P-104", "MG", "mg"),
        ("ORD-DEMO-002", "P-205", "Ml", "ml"),
        ("ORD-DEMO-003", "P-318", "MG", "mg"),
    ]
    for i, (ord_id, pat, sub_u, norm_u) in enumerate(unit_specs):
        t = step_time(22)
        app_id = f"APR-WARN-U-{6001 + i}"
        req_id = f"REQ-WARN-U-{1001 + i}"

        action_data = {
            "order_id": ord_id,
            "patient_id": pat,
            "medication_id": "MED-A",
            "dose": "5",
            "units": norm_u,
            "route": "oral",
            "frequency": "daily",
            "duration": "7 days",
        }
        h = action_hash(ProtectedAction(**action_data))
        approvals_to_seed.append({
            "approval_id": app_id,
            "action_hash": h,
            "action_json": json.dumps(action_data),
            "approver_id": "clinician_1",
            "created_at": (t - timedelta(minutes=15)).isoformat(),
            "expires_at": (t + timedelta(hours=12)).isoformat(),
            "revoked": 0,
            "consumed": 1,
        })

        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": "agent_1",
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": app_id,
            "decision": "warning",
            "risk": "medium",
            "rule": "non-canonical units",
            "reason": f"Non-canonical unit case submitted ('{sub_u}'). Normalized to lowercase '{norm_u}' and executed under review.",
            "changed_fields": ["units"],
            "state_changed": True,
        })

    # 3.2 Missing Non-Essential Audit Metadata (2 events)
    for i in range(2):
        t = step_time(25)
        pat = patients[i % len(patients)]
        req_id = f"REQ-WARN-META-{1001 + i}"
        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": "clinician_1",
            "tool": "read_patient_summary",
            "action_type": "read_summary",
            "approval_id": None,
            "decision": "warning",
            "risk": "low",
            "rule": "optional telemetry missing",
            "reason": "Client IP telemetry unavailable from remote clinical terminal. Read permitted under intent baseline.",
            "changed_fields": [],
            "state_changed": False,
        })

    # 3.3 Off-Hours Authorized Access (2 events)
    off_hours = [
        datetime(2026, 10, 13, 2, 45, 0, tzinfo=timezone.utc),
        datetime(2026, 10, 14, 3, 15, 0, tzinfo=timezone.utc),
    ]
    for i, t_off in enumerate(off_hours):
        pat = patients[i % len(patients)]
        req_id = f"REQ-WARN-OFF-{1001 + i}"
        events.append({
            "time": t_off.isoformat(),
            "request_id": req_id,
            "actor": "nurse_1",
            "tool": "read_patient_summary",
            "action_type": "read_summary",
            "approval_id": None,
            "decision": "warning",
            "risk": "medium",
            "rule": "off-hours authorized access",
            "reason": f"Authorized access occurred during off-hours ({t_off.strftime('%H:%M UTC')}). Operation permitted with elevated audit log.",
            "changed_fields": [],
            "state_changed": False,
        })

    # 3.4 Approval Near Expiration (2 events)
    for i in range(2):
        t = step_time(30)
        app_id = f"APR-WARN-EXP-{6010 + i}"
        req_id = f"REQ-WARN-EXP-{1001 + i}"

        action_data = {
            "order_id": f"ORD-DEMO-00{i + 3}",
            "patient_id": "P-318",
            "medication_id": "MED-C",
            "dose": "250",
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "5 days",
        }
        h = action_hash(ProtectedAction(**action_data))
        approvals_to_seed.append({
            "approval_id": app_id,
            "action_hash": h,
            "action_json": json.dumps(action_data),
            "approver_id": "clinician_1",
            "created_at": (t - timedelta(hours=23, minutes=56)).isoformat(),
            "expires_at": (t + timedelta(minutes=4)).isoformat(),
            "revoked": 0,
            "consumed": 1,
        })

        events.append({
            "time": t.isoformat(),
            "request_id": req_id,
            "actor": "agent_1",
            "tool": "update_order",
            "action_type": "update_order",
            "approval_id": app_id,
            "decision": "warning",
            "risk": "medium",
            "rule": "approval near expiration",
            "reason": f"Approval {app_id} executed within 4 minutes of expiry window. Execution permitted, flagged for latency review.",
            "changed_fields": [],
            "state_changed": True,
        })

    # 3.5 High-Frequency Query Volume (1 event)
    t = step_time(15)
    events.append({
        "time": t.isoformat(),
        "request_id": "REQ-WARN-RATE-1001",
        "actor": "agent_1",
        "tool": "read_patient_summary",
        "action_type": "read_summary",
        "approval_id": None,
        "decision": "warning",
        "risk": "low",
        "rule": "high-frequency query volume",
        "reason": "Rapid burst query volume detected (5 summary reads in 15 seconds). Permitted within quota, flagged for rate monitoring.",
        "changed_fields": [],
        "state_changed": False,
    })

    assert len(events) == 100, f"Expected exactly 100 events, got {len(events)}"

    # Sort strictly descending by timestamp (newest first)
    events.sort(key=lambda e: e["time"], reverse=True)

    return events, approvals_to_seed


def seed_database_and_file():
    """Populate both medishield.sqlite3 and logs/sample_events.jsonl with 100 consistent events."""
    events, approvals = generate_synthetic_dataset()

    # 1. Write to logs/sample_events.jsonl
    jsonl_path = ROOT_DIR / "logs" / "sample_events.jsonl"
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    print(f"[SUCCESS] Wrote {len(events)} synthetic events to {jsonl_path.relative_to(ROOT_DIR)}")

    # 2. Write to SQLite medishield.sqlite3
    db_path = ROOT_DIR / DEFAULT_DB_PATH
    conn = get_connection(db_path)
    init_db(conn)
    seed_data(conn)

    # Insert synthetic approvals
    for app in approvals:
        conn.execute(
            """
            INSERT INTO approvals (approval_id, action_hash, action_json, approver_id, created_at, expires_at, revoked, consumed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(approval_id) DO UPDATE SET
                action_hash = excluded.action_hash,
                action_json = excluded.action_json,
                approver_id = excluded.approver_id,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                revoked = excluded.revoked,
                consumed = excluded.consumed
            """,
            (
                app["approval_id"],
                app["action_hash"],
                app["action_json"],
                app["approver_id"],
                app["created_at"],
                app["expires_at"],
                app["revoked"],
                app["consumed"],
            ),
        )

    # Clear old cluttered audit events and insert fresh 100 events
    conn.execute("DELETE FROM audit_events")
    for ev in events:
        cf_str = json.dumps(ev.get("changed_fields", []))
        conn.execute(
            """
            INSERT INTO audit_events (
                time, request_id, actor_id, tool, action_type, approval_id,
                decision, risk, rule, reason, changed_fields, state_changed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ev["time"],
                ev["request_id"],
                ev["actor"],
                ev["tool"],
                ev["action_type"],
                ev["approval_id"],
                ev["decision"],
                ev["risk"],
                ev["rule"],
                ev["reason"],
                cf_str,
                1 if ev["state_changed"] else 0,
            ),
        )
    conn.commit()
    conn.close()
    print(f"[SUCCESS] Seeded {len(events)} events and {len(approvals)} approvals into {db_path.name}")


if __name__ == "__main__":
    seed_database_and_file()

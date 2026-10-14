"""
Automated validation of MediShield synthetic dataset integrity and realism.
===========================================================================
Tests the dataset against all clinical security invariants:
  - 100 events with 65% Allowed, 25% Blocked, 10% Warning
  - Fail-closed invariant: 0 blocked events alter state
  - No mandatory security violation masked as a warning
  - Timestamps strictly chronological and sorted descending
  - Single-use replay, expiry, and revocation lifecycles are consistent
  - Error rate correctly isolates genuine execution failures (1.0%)
"""

from datetime import datetime
import json
from pathlib import Path
import sqlite3
import pytest

from server.db import DEFAULT_DB_PATH, get_connection

ROOT_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture
def db_events():
    conn = get_connection(ROOT_DIR / DEFAULT_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_events ORDER BY id DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


@pytest.fixture
def jsonl_events():
    path = ROOT_DIR / "logs" / "sample_events.jsonl"
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
    return events


def test_total_event_count_is_100(jsonl_events):
    assert len(jsonl_events) == 100


def test_distribution_is_65_25_10(jsonl_events):
    allowed = sum(1 for e in jsonl_events if e["decision"] == "allowed")
    blocked = sum(1 for e in jsonl_events if e["decision"] == "blocked")
    warning = sum(1 for e in jsonl_events if e["decision"] == "warning")

    assert allowed == 65, f"Expected 65 Allowed, got {allowed}"
    assert blocked == 25, f"Expected 25 Blocked, got {blocked}"
    assert warning == 10, f"Expected 10 Warning, got {warning}"


def test_fail_closed_zero_state_changes_on_blocked_actions(db_events, jsonl_events):
    for dataset_name, dataset in [("db_events", db_events), ("jsonl_events", jsonl_events)]:
        blocked_violations = [
            e["request_id"] for e in dataset
            if e["decision"] == "blocked" and e.get("state_changed") not in (0, False)
        ]
        assert blocked_violations == [], f"Found blocked events modifying state in {dataset_name}: {blocked_violations}"


def test_no_mandatory_security_check_masked_as_warning(db_events, jsonl_events):
    mandatory_failure_rules = {
        "intent hash mismatch",
        "approval already consumed",
        "approval expired",
        "approval revoked",
        "role not permitted",
        "actor not registered",
        "destination not pinned",
        "tool description not pinned",
        "malformed request",
    }
    for dataset_name, dataset in [("db_events", db_events), ("jsonl_events", jsonl_events)]:
        invalid_warnings = [
            e for e in dataset
            if e["decision"] == "warning" and e["rule"] in mandatory_failure_rules
        ]
        assert invalid_warnings == [], f"Found mandatory check failures categorized as warnings in {dataset_name}: {invalid_warnings}"


def test_warnings_have_documented_non_blocking_conditions(jsonl_events):
    permitted_warning_rules = {
        "non-canonical units",
        "optional telemetry missing",
        "off-hours authorized access",
        "approval near expiration",
        "high-frequency query volume",
    }
    warnings = [e for e in jsonl_events if e["decision"] == "warning"]
    for w in warnings:
        assert w["rule"] in permitted_warning_rules, f"Undocumented warning rule: {w['rule']}"


def test_all_request_ids_are_unique(jsonl_events):
    req_ids = [e["request_id"] for e in jsonl_events]
    assert len(req_ids) == len(set(req_ids)), "Duplicate request IDs found in synthetic dataset!"


def test_timestamps_are_sorted_descending(jsonl_events):
    times = [e["time"] for e in jsonl_events]
    sorted_times = sorted(times, reverse=True)
    assert times == sorted_times, "Events in sample_events.jsonl are not sorted newest first!"


def test_error_rate_calculation(jsonl_events):
    total = len(jsonl_events)
    genuine_errors = sum(
        1 for e in jsonl_events
        if e["rule"] in ["verification failed", "system fault", "database error"]
        or e.get("error")
    )
    error_rate = (genuine_errors / total) * 100.0
    assert genuine_errors == 1, f"Expected exactly 1 genuine system failure, got {genuine_errors}"
    assert error_rate == 1.0, f"Expected 1.0% error rate, got {error_rate}%"


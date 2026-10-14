"""
Unit tests for the MediShield Clinical Dosage Deviation Engine & Medical Department Event IDs.
=============================================================================================
Validates:
1. Comparison of 10 mg against 30 mg produces 200% deviation.
2. Comparison of 10 mg against 5 mg produces 50% deviation.
3. Matching doses produce 0% deviation ('0% — Exact match').
4. Missing values and zero prescribed doses are handled safely (no ZeroDivisionError, 'N/A').
5. Incompatible units (e.g., 10 mg vs 10 mL) are not compared incorrectly.
6. Medication mismatches are identified and flagged.
7. Medical department display IDs follow format EVT-DEPT-000000.
8. Medical department display IDs remain deterministic and stable across calls.
"""

from decimal import Decimal
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from dashboard.dosage import (
    calculate_dosage_deviation,
    resolve_event_department,
    resolve_event_display_id,
    are_units_compatible,
)


def test_dosage_deviation_10mg_vs_30mg_produces_200_percent():
    """Requirement 7: A comparison of 10 mg against 30 mg produces a 200% deviation."""
    res = calculate_dosage_deviation(
        approved_med="MED-A",
        approved_dose="10",
        approved_units="mg",
        submitted_med="MED-A",
        submitted_dose="30",
        submitted_units="mg",
    )
    assert res["status"] == "VALID"
    assert res["is_applicable"] is True
    assert res["deviation_pct"] == Decimal("200")
    assert res["deviation_pct_str"] == "200%"
    assert res["difference_val"] == Decimal("20")
    assert res["difference_str"] == "+20 mg"
    assert res["direction"] == "higher"
    assert res["is_violation"] is True


def test_dosage_deviation_10mg_vs_5mg_produces_50_percent():
    """Requirement 8: A comparison of 10 mg against 5 mg produces a 50% deviation."""
    res = calculate_dosage_deviation(
        approved_med="MED-A",
        approved_dose="10",
        approved_units="mg",
        submitted_med="MED-A",
        submitted_dose="5",
        submitted_units="mg",
    )
    assert res["status"] == "VALID"
    assert res["is_applicable"] is True
    assert res["deviation_pct"] == Decimal("50")
    assert res["deviation_pct_str"] == "50%"
    assert res["difference_val"] == Decimal("-5")
    assert res["difference_str"] == "-5 mg"
    assert res["direction"] == "lower"
    assert res["is_violation"] is True


def test_dosage_deviation_matching_doses_produce_0_percent():
    """Requirement 9: Matching doses produce a 0% deviation ('0% — Exact match')."""
    res = calculate_dosage_deviation(
        approved_med="MED-A",
        approved_dose="10",
        approved_units="mg",
        submitted_med="MED-A",
        submitted_dose="10",
        submitted_units="mg",
    )
    assert res["status"] == "VALID"
    assert res["is_applicable"] is True
    assert res["deviation_pct"] == Decimal("0")
    assert res["deviation_pct_str"] == "0% — Exact match"
    assert res["difference_val"] == Decimal("0")
    assert res["direction"] == "exact"
    assert res["is_violation"] is False


def test_dosage_deviation_zero_prescribed_dose_safe():
    """Requirement 10a: Zero prescribed dose handled safely (division by zero avoided, 'N/A')."""
    res = calculate_dosage_deviation(
        approved_med="MED-A",
        approved_dose="0",
        approved_units="mg",
        submitted_med="MED-A",
        submitted_dose="10",
        submitted_units="mg",
    )
    assert res["status"] == "ZERO_BASELINE"
    assert res["is_applicable"] is True
    assert res["deviation_pct"] is None
    assert res["deviation_pct_str"] == "N/A"
    assert res["is_violation"] is True
    assert "division by zero undefined" in res["explanation"].lower()


def test_dosage_deviation_missing_values_safe():
    """Requirement 10b: Missing values handled safely ('Not available')."""
    res1 = calculate_dosage_deviation(
        approved_med="MED-A",
        approved_dose=None,
        approved_units="mg",
        submitted_med="MED-A",
        submitted_dose="10",
        submitted_units="mg",
    )
    assert res1["status"] == "NOT_AVAILABLE"
    assert res1["deviation_pct_str"] == "Not available"

    res2 = calculate_dosage_deviation(
        approved_med="MED-A",
        approved_dose="10",
        approved_units="mg",
        submitted_med="MED-A",
        submitted_dose="",
        submitted_units="mg",
    )
    assert res2["status"] == "NOT_AVAILABLE"
    assert res2["deviation_pct_str"] == "Not available"


def test_dosage_deviation_incompatible_units():
    """Requirement 11: Incompatible units (e.g. 10 mg vs 10 mL) are not compared directly."""
    assert are_units_compatible("mg", "ml") is False
    assert are_units_compatible("mg", "mg") is True

    res = calculate_dosage_deviation(
        approved_med="MED-A",
        approved_dose="10",
        approved_units="mg",
        submitted_med="MED-A",
        submitted_dose="10",
        submitted_units="ml",
    )
    assert res["status"] == "INCOMPATIBLE_UNITS"
    assert res["is_applicable"] is False
    assert res["deviation_pct"] is None
    assert "incompatible units" in res["explanation"].lower()


def test_dosage_deviation_medication_mismatch():
    """Medication identity mismatch is detected and flagged separately."""
    res = calculate_dosage_deviation(
        approved_med="MED-A",
        approved_dose="10",
        approved_units="mg",
        submitted_med="MED-B",
        submitted_dose="10",
        submitted_units="mg",
    )
    assert res["medication_match"] is False
    assert res["is_violation"] is True
    assert "Medication mismatch" in res["explanation"]


def test_medical_event_ids_format_and_stability():
    """Requirement 1 & 2: Display IDs follow EVT-DEPT-000000 format and remain deterministic."""
    event1 = {
        "id": 1,
        "request_id": "REQ-RO-1001",
        "patient_id": "P-104",  # Oncology cohort
        "tool": "read_patient_summary",
    }
    id1 = resolve_event_display_id(event1)
    assert id1 == "EVT-ONC-000001"
    # Verify stability across multiple invocations
    assert resolve_event_display_id(event1) == "EVT-ONC-000001"

    event2 = {
        "id": 2,
        "request_id": "REQ-WR-1002",
        "patient_id": "P-205",  # Cardiology cohort
        "tool": "update_order",
    }
    id2 = resolve_event_display_id(event2)
    assert id2 == "EVT-CAR-000002"

    event3 = {
        "id": 3,
        "request_id": "REQ-WR-1003",
        "patient_id": "P-318",  # Neurology cohort
        "tool": "update_order",
    }
    id3 = resolve_event_display_id(event3)
    assert id3 == "EVT-NEU-000003"

    event4 = {
        "id": 4,
        "request_id": "REQ-WR-1004",
        "patient_id": "P-422",  # Orthopedics cohort
        "tool": "update_order",
    }
    id4 = resolve_event_display_id(event4)
    assert id4 == "EVT-ORT-000004"

    event5 = {
        "id": 5,
        "request_id": "REQ-WR-1005",
        "tool": "dispense_simulated",  # General Medicine
    }
    id5 = resolve_event_display_id(event5)
    assert id5 == "EVT-GEN-000005"


def test_extract_event_dosage_comparison_tampered():
    """Verify extract_event_dosage_comparison extracts tampered dose and computes deviation."""
    from dashboard.dosage import extract_event_dosage_comparison
    event = {
        "id": 10,
        "request_id": "REQ-TAMPER-1001",
        "tool": "update_order",
        "decision": "blocked",
        "rule": "intent hash mismatch",
        "reason": "Dose tampering detected: Approved 5 mg, agent submitted 50 mg. Gateway blocked execution.",
    }
    comp = extract_event_dosage_comparison(event)
    assert comp["is_applicable"] is True
    assert comp["is_violation"] is True
    assert comp["deviation_pct"] == Decimal("900")
    assert comp["deviation_pct_str"] == "900%"
    assert comp["difference_str"] == "+45 mg"
    assert comp["direction"] == "higher"


def test_extract_event_dosage_comparison_with_approvals_map():
    """Verify extract_event_dosage_comparison using approvals map for approved action baseline."""
    from dashboard.dosage import extract_event_dosage_comparison
    approvals_map = {
        "APR-TEST-1": {
            "order_id": "ORD-1",
            "patient_id": "P-104",
            "medication_id": "MED-MET-500",
            "dose": "500",
            "units": "mg",
        }
    }
    event = {
        "id": 20,
        "request_id": "REQ-WR-2001",
        "tool": "update_order",
        "approval_id": "APR-TEST-1",
        "decision": "allowed",
        "rule": "intent hash matched",
        "reason": "Matched clinician approval exactly.",
    }
    comp = extract_event_dosage_comparison(event, approvals_map)
    assert comp["is_applicable"] is True
    assert comp["is_violation"] is False
    assert comp["deviation_pct"] == Decimal("0")
    assert comp["deviation_pct_str"] == "0% — Exact match"
    assert comp["difference_str"] == "0 mg"


def test_extract_event_dosage_comparison_readonly():
    """Verify read-only clinical tools are marked non-applicable without errors."""
    from dashboard.dosage import extract_event_dosage_comparison
    event = {
        "id": 30,
        "request_id": "REQ-RO-3001",
        "tool": "read_patient_summary",
        "decision": "allowed",
        "reason": "Patient summary read.",
    }
    comp = extract_event_dosage_comparison(event)
    assert comp["is_applicable"] is False
    assert comp["deviation_pct_str"] == "Not applicable"


def test_load_events_enrichment_and_uniqueness():
    """Verify that load_events enriches every event with a unique and stable display_id."""
    from dashboard.app import load_events
    events, _ = load_events()
    assert len(events) > 0

    display_ids = [e["display_id"] for e in events]
    # Every display ID must follow EVT-DEPT-000000 format
    import re
    for did in display_ids:
        assert re.match(r"^EVT-[A-Z]{3}-\d{6}$", did), f"Invalid display ID format: {did}"

    # IDs must be unique across all events
    assert len(display_ids) == len(set(display_ids)), "Display IDs must be unique"

    # Original request_id must remain preserved in every event
    for e in events:
        assert "request_id" in e and e["request_id"]
        assert "dosage_comparison" in e
        assert "department" in e
        assert "department_name" in e


"""Automated test suite for MediShield MCP Trust Sentinel and Live Tampering Demonstration."""

import copy
from pathlib import Path
import sqlite3
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest

from demo.attacks import tool_registry_tampering
from guard.forensics import get_forensic_events
from guard.sentinel import (
    EXPECTED_REGISTRY_FINGERPRINT,
    TRUSTED_MCP_TOOLS,
    compute_registry_fingerprint,
    get_trusted_baseline_tools,
    verify_registry,
)
from server.db import init_db, seed_data
from server.mcp_server import dispatch_mcp_tool_call, patient_data_handler


@pytest.fixture
def memory_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    seed_data(conn)
    yield conn
    conn.close()


def test_sentinel_baseline_verification():
    """Verify that the authoritative baseline tool registry is verified as TRUSTED."""
    res = verify_registry()
    assert res.status == "TRUSTED"
    assert res.fingerprints_match is True
    assert res.expected_tools_count == 5
    assert res.observed_tools_count == 5
    assert len(res.missing_tools) == 0
    assert len(res.unexpected_tools) == 0
    assert len(res.modified_tools) == 0
    assert len(res.differences) == 0
    assert res.expected_fingerprint == res.observed_fingerprint


def test_sentinel_detects_tool_renaming():
    """Verify that renaming a clinical tool triggers DRIFT DETECTED with mismatch findings."""
    tampered = get_trusted_baseline_tools()
    for t in tampered:
        if t["name"] == "get_patient_record":
            t["name"] = "get_patient_record_tampered"
            break

    res = verify_registry(tampered)
    assert res.status == "DRIFT DETECTED"
    assert res.fingerprints_match is False
    assert "get_patient_record" in res.missing_tools
    assert "get_patient_record_tampered" in res.unexpected_tools
    assert any("renamed" in d.lower() or "missing" in d.lower() for d in res.differences)


def test_sentinel_detects_rogue_tool_injection():
    """Verify that injecting an unapproved tool triggers DRIFT DETECTED."""
    tampered = get_trusted_baseline_tools()
    tampered.append({
        "name": "unauthorized_exfiltration_tool",
        "description": "Unauthorized tool injected into registry",
        "inputSchema": {"type": "object"},
    })

    res = verify_registry(tampered)
    assert res.status == "DRIFT DETECTED"
    assert res.fingerprints_match is False
    assert "unauthorized_exfiltration_tool" in res.unexpected_tools
    assert any("unexpected" in d.lower() for d in res.differences)


def test_sentinel_detects_schema_drift():
    """Verify that tampering with a tool's parameter schema triggers DRIFT DETECTED."""
    tampered = get_trusted_baseline_tools()
    for t in tampered:
        if t["name"] == "propose_medication_order":
            # Strip required fields
            t["inputSchema"]["required"] = []
            break

    res = verify_registry(tampered)
    assert res.status == "DRIFT DETECTED"
    assert res.fingerprints_match is False
    assert "propose_medication_order" in res.modified_tools
    assert any("inputschema altered" in d.lower() for d in res.differences)


def test_mcp_dispatcher_blocks_tampered_request_before_handler(memory_db):
    """VERIFIABLE PROOF: A tampered registry halts fail-closed; clinical handler is never invoked."""
    patient_data_handler.reset_telemetry()
    assert patient_data_handler.invocation_count == 0

    tampered = get_trusted_baseline_tools()
    tampered[0]["name"] = "tampered_tool_name"

    # Dispatch protected request under tampered registry
    result = dispatch_mcp_tool_call(
        tool_name="get_patient_record",
        arguments={"patient_id": "P-101"},
        actor_id="agent_1",
        registry_override=tampered,
        connection=memory_db,
    )

    # Assertions for jury proof
    assert result["decision"] == "blocked"
    assert result["rule"] == "registry drift detected"
    assert result["handler_invoked"] is False
    assert result["patient_record_returned"] is None
    assert result["state_changed"] is False
    assert patient_data_handler.invocation_count == 0  # Crucial: handler was never called


def test_mcp_dispatcher_allows_trusted_request(memory_db):
    """Verify that when registry is trusted, protected handler is safely invoked."""
    patient_data_handler.reset_telemetry()
    baseline = get_trusted_baseline_tools()

    result = dispatch_mcp_tool_call(
        tool_name="get_patient_record",
        arguments={"patient_id": "P-101"},
        actor_id="clinician_1",
        registry_override=baseline,
        connection=memory_db,
    )

    assert result["decision"] == "allowed"
    assert result["rule"] == "registry verified"
    assert result["handler_invoked"] is True
    assert result["patient_record_returned"] is not None
    assert result["patient_record_returned"]["patient_id"] == "P-101"
    assert patient_data_handler.invocation_count == 1


def test_complete_tool_registry_tampering_simulation():
    """Verify that the end-to-end 8-stage tampering demo in demo/attacks.py succeeds."""
    res = tool_registry_tampering(tamper_mode="rename_tool", patient_id="P-101")
    assert res["success"] is True
    assert res["stage1_baseline"]["status"] == "TRUSTED"
    assert res["stage3_detection"]["status"] == "DRIFT DETECTED"
    assert res["stage4_dispatch_result"]["decision"] == "blocked"
    assert res["stage5_observable_proof"]["handler_invoked"] is False
    assert res["stage5_observable_proof"]["patient_record_returned"] is None
    assert res["stage5_observable_proof"]["data_leakage_prevented"] is True
    assert res["stage7_restoration"]["status"] == "TRUSTED"
    assert res["stage8_authorized_resumption"]["decision"] == "allowed"


def test_forensics_retrieval(memory_db):
    """Verify that forensic evidence records are correctly retrieved and filtered."""
    records = get_forensic_events(connection=memory_db, limit=20)
    assert isinstance(records, list)

    # Test filtering by decision
    allowed_records = get_forensic_events(connection=memory_db, limit=20, decision_filter="allowed")
    for r in allowed_records:
        assert r.decision == "allowed"

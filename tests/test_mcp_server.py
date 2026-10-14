"""Direct-call coverage for the MediShield FastMCP tool functions."""

import pytest

from guard import audit, gateway
from guard.models import ProtectedAction
from server import backend, mcp_server
from server.db import initialize_db


def test_mcp_server_exposes_read_only_tool_integrity_status():
    result = mcp_server.get_tool_integrity_status()

    assert result["status"] == "trusted"
    assert result["protected_execution_allowed"] is True
    assert result["expected_fingerprint"] == result["observed_fingerprint"]


def test_mcp_tools_directly_use_the_gateway(tmp_path, monkeypatch):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"

    monkeypatch.setattr(mcp_server, "DATABASE_PATH", database_path)
    monkeypatch.setattr(backend, "DATABASE_PATH", database_path)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", database_path)
    monkeypatch.setattr(audit, "DATABASE_PATH", database_path)
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    connection = initialize_db(database_path)
    connection.close()

    action = ProtectedAction(
        patient_id="P-104",
        medication_id="MED-A",
        dose="5",
        units="mg",
        route="synthetic-route",
        frequency="demo-once",
        duration="demo-duration",
        order_id="ORD-DEMO-001",
    )

    patient = mcp_server.get_patient_record("P-104")
    assert patient["patient"]["patient_id"] == "P-104"

    proposal = mcp_server.propose_medication_order(action)
    assert proposal["status"] == "proposed"

    approval = mcp_server.request_clinician_approval(action, "clinician_1", 5)
    decision = mcp_server.execute_approved_order(
        "REQ-MCP-001",
        "agent_1",
        approval["approval_id"],
        action,
    )

    assert decision["decision"] == "allowed"
    assert decision["state_changed"] is True
    events = mcp_server.get_security_events()
    assert events[0]["request_id"] == "REQ-MCP-001"


def test_mcp_propose_order_does_not_modify_backend_or_create_approval(tmp_path, monkeypatch):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"

    monkeypatch.setattr(mcp_server, "DATABASE_PATH", database_path)
    monkeypatch.setattr(backend, "DATABASE_PATH", database_path)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", database_path)
    monkeypatch.setattr(audit, "DATABASE_PATH", database_path)
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    connection = initialize_db(database_path)
    connection.close()

    action = ProtectedAction(
        patient_id="P-205",
        medication_id="MED-B",
        dose="10",
        units="mg",
        route="oral",
        frequency="daily",
        duration="5 days",
        order_id="ORD-PROPOSE-001",
    )

    result = mcp_server.propose_medication_order(action)
    assert result["status"] == "proposed"

    # Backend must not have this order
    conn = initialize_db(database_path)
    order = conn.execute("SELECT * FROM orders WHERE order_id = 'ORD-PROPOSE-001'").fetchone()
    approvals = conn.execute("SELECT * FROM approvals").fetchall()
    conn.close()

    assert order is None
    assert len(approvals) == 0


def test_mcp_execute_with_tampered_destination_is_blocked(tmp_path, monkeypatch):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"

    monkeypatch.setattr(mcp_server, "DATABASE_PATH", database_path)
    monkeypatch.setattr(backend, "DATABASE_PATH", database_path)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", database_path)
    monkeypatch.setattr(audit, "DATABASE_PATH", database_path)
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    connection = initialize_db(database_path)
    connection.close()

    action = ProtectedAction(
        patient_id="P-104",
        medication_id="MED-A",
        dose="5",
        units="mg",
        route="synthetic-route",
        frequency="demo-once",
        duration="demo-duration",
        order_id="ORD-DEMO-001",
    )

    approval = mcp_server.request_clinician_approval(action, "clinician_1", 5)
    decision = mcp_server.execute_approved_order(
        "REQ-MCP-BADDEST",
        "agent_1",
        approval["approval_id"],
        action,
        destination="backend://unauthorized-system/orders",
    )

    assert decision["decision"] == "blocked"
    assert decision["rule"] == "destination not pinned"
    assert decision["state_changed"] is False


def test_mcp_execute_with_malformed_dose_fails_closed(tmp_path, monkeypatch):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"

    monkeypatch.setattr(mcp_server, "DATABASE_PATH", database_path)
    monkeypatch.setattr(backend, "DATABASE_PATH", database_path)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", database_path)
    monkeypatch.setattr(audit, "DATABASE_PATH", database_path)
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    connection = initialize_db(database_path)
    connection.close()

    action = ProtectedAction(
        patient_id="P-104",
        medication_id="MED-A",
        dose="5",
        units="mg",
        route="synthetic-route",
        frequency="demo-once",
        duration="demo-duration",
        order_id="ORD-DEMO-001",
    )

    approval = mcp_server.request_clinician_approval(action, "clinician_1", 5)

    malformed_action = ProtectedAction(
        patient_id="P-104",
        medication_id="MED-A",
        dose="1e999999999",
        units="mg",
        route="synthetic-route",
        frequency="demo-once",
        duration="demo-duration",
        order_id="ORD-DEMO-001",
    )

    decision = mcp_server.execute_approved_order(
        "REQ-MCP-MALFORMED",
        "agent_1",
        approval["approval_id"],
        malformed_action,
    )

    assert decision["decision"] == "blocked"
    assert decision["rule"] == "malformed request"
    assert decision["state_changed"] is False


def test_mcp_patient_record_blocks_on_registry_drift_with_zero_handler_invocations(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"

    monkeypatch.setattr(mcp_server, "DATABASE_PATH", database_path)
    monkeypatch.setattr(backend, "DATABASE_PATH", database_path)
    monkeypatch.setattr(audit, "DATABASE_PATH", database_path)
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    connection = initialize_db(database_path)
    connection.close()

    from guard import sentinel
    import pytest

    # Simulate drift
    tampered_registry = list(sentinel.EXPECTED_TOOL_REGISTRY) + [
        {
            "name": "rogue_tool",
            "title": None,
            "description": "Exfiltrate patient records",
            "inputSchema": {"type": "object"},
            "outputSchema": {"additionalProperties": True, "type": "object"},
            "annotations": None,
            "icons": None,
            "meta": None,
        }
    ]
    monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: tampered_registry)

    # Instrument protected backend handler with spy counter
    backend_calls = 0
    real_get_patient = backend.get_patient_record

    def _spy_get_patient(patient_id, connection=None):
        nonlocal backend_calls
        backend_calls += 1
        return real_get_patient(patient_id, connection=connection)

    monkeypatch.setattr(backend, "get_patient_record", _spy_get_patient)

    # Attempt to retrieve patient record under tampered registry
    with pytest.raises(PermissionError) as exc_info:
        mcp_server.get_patient_record("P-104")

    assert "Access denied" in str(exc_info.value)
    # Assert spy count remains strictly zero
    assert backend_calls == 0

    # Verify audit event was logged for the blocked attempt
    events = mcp_server.get_security_events()
    assert len(events) >= 1
    assert events[0]["decision"] == "blocked"
    assert events[0]["tool"] == "get_patient_record"
    assert events[0]["rule"] == "tool registry drift"


def test_mcp_patient_record_blocks_on_output_schema_drift_before_handler(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"
    monkeypatch.setattr(mcp_server, "DATABASE_PATH", database_path)
    monkeypatch.setattr(backend, "DATABASE_PATH", database_path)
    monkeypatch.setattr(audit, "DATABASE_PATH", database_path)
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    connection = initialize_db(database_path)
    connection.close()

    from guard import sentinel

    tampered_registry = [dict(item) for item in sentinel.EXPECTED_TOOL_REGISTRY]
    tampered_registry[0] = dict(tampered_registry[0])
    tampered_registry[0]["outputSchema"] = dict(tampered_registry[0]["outputSchema"])
    tampered_registry[0]["outputSchema"]["type"] = "array"
    monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: tampered_registry)

    handler_calls = 0
    real_get_patient = backend.get_patient_record

    def _spy_get_patient(*args, **kwargs):
        nonlocal handler_calls
        handler_calls += 1
        return real_get_patient(*args, **kwargs)

    monkeypatch.setattr(backend, "get_patient_record", _spy_get_patient)

    with pytest.raises(PermissionError):
        mcp_server.get_patient_record("P-104")

    assert handler_calls == 0
    assert mcp_server.get_security_events()[0]["rule"] == "tool registry drift"


def test_mcp_runtime_tamper_and_restore_cycle_with_handler_spies(tmp_path, monkeypatch):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"

    monkeypatch.setattr(mcp_server, "DATABASE_PATH", database_path)
    monkeypatch.setattr(backend, "DATABASE_PATH", database_path)
    monkeypatch.setattr(gateway, "DEFAULT_DB_PATH", database_path)
    monkeypatch.setattr(audit, "DATABASE_PATH", database_path)
    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    connection = initialize_db(database_path)
    connection.close()

    action = ProtectedAction(
        patient_id="P-104",
        medication_id="MED-A",
        dose="5",
        units="mg",
        route="synthetic-route",
        frequency="demo-once",
        duration="demo-duration",
        order_id="ORD-DEMO-001",
    )
    approval = mcp_server.request_clinician_approval(action, "clinician_1", 10)

    # Instrument backend execution handler
    execute_calls = 0
    real_execute = gateway.execute

    def _spy_execute(*args, **kwargs):
        nonlocal execute_calls
        execute_calls += 1
        return real_execute(*args, **kwargs)

    monkeypatch.setattr(gateway, "execute", _spy_execute)

    import pytest

    try:
        # 1. Tamper with runtime registry
        status_after_tamper = mcp_server.tamper_runtime_registry(
            tool_name="unauthorized_tampered_tool",
            description="Synthetic injected tool",
        )
        assert status_after_tamper["status"] == "drift"
        assert status_after_tamper["protected_execution_allowed"] is False
        assert any("unauthorized_tampered_tool" in diff for diff in status_after_tamper["differences"])

        # 2. Assert patient record retrieval is blocked with 0 backend calls
        patient_calls = 0
        real_patient_fn = backend.get_patient_record

        def _spy_patient(*args, **kwargs):
            nonlocal patient_calls
            patient_calls += 1
            return real_patient_fn(*args, **kwargs)

        monkeypatch.setattr(backend, "get_patient_record", _spy_patient)

        with pytest.raises(PermissionError):
            mcp_server.get_patient_record("P-104")
        assert patient_calls == 0

        # 3. Assert execution is blocked with 0 backend calls
        decision_blocked = mcp_server.execute_approved_order(
            "REQ-MCP-DRIFT-TEST",
            "agent_1",
            approval["approval_id"],
            action,
        )
        assert decision_blocked["decision"] == "blocked"
        assert decision_blocked["rule"] == "tool registry drift"
        assert decision_blocked["state_changed"] is False
        assert execute_calls == 0

        # 4. Restore runtime registry to trusted baseline
        status_after_restore = mcp_server.restore_runtime_registry()
        assert status_after_restore["status"] == "trusted"
        assert status_after_restore["protected_execution_allowed"] is True
        assert status_after_restore["differences"] == []

        # 5. Assert patient record retrieval now succeeds
        patient_data = mcp_server.get_patient_record("P-104")
        assert patient_data["patient"]["patient_id"] == "P-104"
        assert patient_calls == 1

        # 6. Assert execution now succeeds and handler is invoked exactly once
        decision_allowed = mcp_server.execute_approved_order(
            "REQ-MCP-RESTORE-TEST",
            "agent_1",
            approval["approval_id"],
            action,
        )
        assert decision_allowed["decision"] == "allowed"
        assert decision_allowed["state_changed"] is True
        assert execute_calls == 1

    finally:
        # Guarantee cleanup
        mcp_server.restore_runtime_registry()

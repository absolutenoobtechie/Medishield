"""Direct-call coverage for the MediShield FastMCP tool functions."""

from guard import audit, gateway
from guard.models import ProtectedAction
from server import backend, mcp_server
from server.db import initialize_db


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

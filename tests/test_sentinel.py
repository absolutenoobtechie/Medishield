"""Focused tests for MCP registry integrity and forensic evidence."""

import copy
import sqlite3
import json
from datetime import datetime, timedelta, timezone

import pytest

from guard import sentinel
from guard.approval import compute_approval_mac
from guard.forensics import evidence_for_request
from guard.gateway import verify_execution
from guard.models import ExecutionRequest, ProtectedAction
from guard.intent import action_hash, canonicalize_action
from guard.policy import PINNED_DESTINATIONS
from server.db import init_db, seed_data


DESTINATION = PINNED_DESTINATIONS["update_order"]


def _registry():
    return list(copy.deepcopy(sentinel.EXPECTED_TOOL_REGISTRY))


def _action() -> ProtectedAction:
    return ProtectedAction(
        patient_id="P-104",
        medication_id="MED-A",
        dose="5",
        units="mg",
        route="oral",
        frequency="daily",
        duration="7 days",
        order_id="ORD-DEMO-001",
    )


def _approval(connection, approval_id="APR-SENTINEL-001"):
    action = _action()
    action_json = canonicalize_action(action)
    action_digest = action_hash(action)
    now = datetime.now(timezone.utc)
    created = now - timedelta(minutes=1)
    expires = now + timedelta(hours=1)
    created_at = created.isoformat().replace("+00:00", "Z")
    expires_at = expires.isoformat().replace("+00:00", "Z")
    connection.execute(
        """
        INSERT INTO approvals(
            approval_id, action_hash, action_json, approver_id,
            created_at, expires_at, revoked, consumed, approval_mac
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
        """,
        (
            approval_id,
            action_digest,
            action_json,
            "clinician_1",
            created_at,
            expires_at,
            compute_approval_mac(
                approval_id=approval_id,
                action_json=action_json,
                action_hash=action_digest,
                approver_id="clinician_1",
                created_at=created_at,
                expires_at=expires_at,
            ),
        ),
    )
    connection.commit()
    return approval_id


def test_current_registry_is_trusted():
    result = sentinel.check_registry()

    assert result.status == "trusted"
    assert result.protected_execution_allowed is True
    assert result.expected_fingerprint == result.observed_fingerprint
    assert result.differences == []


def test_registry_fingerprint_is_independent_of_mapping_key_order():
    registry = _registry()
    reordered = json.loads(json.dumps(registry, sort_keys=True))

    assert sentinel.registry_fingerprint(registry) == sentinel.registry_fingerprint(reordered)


def test_output_schema_fingerprint_is_deterministic_and_detects_tampering():
    registry = _registry()
    reordered = json.loads(json.dumps(registry, sort_keys=True))
    assert sentinel.registry_fingerprint(registry) == sentinel.registry_fingerprint(reordered)

    tampered = _registry()
    tampered[0]["outputSchema"]["type"] = "array"
    result = sentinel.check_registry(tampered)

    assert sentinel.registry_fingerprint(tampered) != sentinel.registry_fingerprint(registry)
    assert result.status == "drift"
    assert result.protected_execution_allowed is False
    assert "changed output schema: get_patient_record" in result.differences
    assert "changed output schema: get_patient_record" in result.explanation


@pytest.mark.parametrize(
    "mutation",
    [
        lambda registry: registry[0].pop("outputSchema"),
        lambda registry: registry[0].update(outputSchema="not-a-schema"),
    ],
)
def test_missing_or_malformed_output_schema_is_unverifiable(mutation):
    registry = _registry()
    mutation(registry)

    result = sentinel.check_registry(registry)

    assert result.status == "unverifiable"
    assert result.protected_execution_allowed is False
    assert result.observed_fingerprint is None


@pytest.mark.parametrize(
    ("mutation", "expected_difference"),
    [
        (
            lambda registry: registry + [
                {
                    "name": "unexpected_tool",
                    "title": None,
                    "description": "Synthetic unexpected tool.",
                    "inputSchema": {"type": "object"},
                    "outputSchema": {"additionalProperties": True, "type": "object"},
                    "annotations": None,
                    "icons": None,
                    "meta": None,
                }
            ],
            "unexpected tool: unexpected_tool",
        ),
        (lambda registry: registry[1:], "missing tool: get_patient_record"),
        (
            lambda registry: [dict(registry[0], name="renamed_patient_tool")] + registry[1:],
            "renamed tool candidate: get_patient_record -> renamed_patient_tool",
        ),
        (
            lambda registry: [
                dict(
                    item,
                    inputSchema=copy.deepcopy(item["inputSchema"]),
                )
                for item in registry
            ],
            None,
        ),
    ],
)
def test_registry_differences_are_explained(mutation, expected_difference):
    registry = mutation(_registry())
    if expected_difference is None:
        registry[0]["inputSchema"]["properties"]["patient_id"]["type"] = "integer"
        expected_difference = "changed input schema: get_patient_record"

    result = sentinel.check_registry(registry)

    assert result.status == "drift"
    assert result.protected_execution_allowed is False
    assert expected_difference in result.differences


def test_malformed_baseline_blocks_safely(monkeypatch):
    observed = _registry()
    monkeypatch.setattr(sentinel, "EXPECTED_TOOL_REGISTRY", {})

    result = sentinel.check_registry(observed)

    assert result.status == "baseline_invalid"
    assert result.protected_execution_allowed is False
    assert "malformed trusted registry baseline" in result.differences[0]


def test_missing_baseline_blocks_safely(monkeypatch):
    observed = _registry()
    monkeypatch.setattr(sentinel, "EXPECTED_TOOL_REGISTRY", None)

    result = sentinel.check_registry(observed)

    assert result.status == "baseline_invalid"
    assert result.protected_execution_allowed is False
    assert "missing or malformed trusted registry baseline" in result.differences[0]


def test_registry_inspection_failure_is_unverifiable(monkeypatch):
    def fail_inspection():
        raise sentinel.RegistryInspectionError("synthetic inspection failure")

    monkeypatch.setattr(sentinel, "inspect_runtime_registry", fail_inspection)

    result = sentinel.check_registry()

    assert result.status == "unverifiable"
    assert result.protected_execution_allowed is False
    assert result.observed_fingerprint is None


def test_interface_metadata_drift_is_explained():
    registry = _registry()
    registry[0]["description"] = "Changed synthetic description."

    result = sentinel.check_registry(registry)

    assert result.status == "drift"
    assert "changed interface metadata: get_patient_record.description" in result.differences


def test_registry_drift_blocks_without_consuming_or_changing_order(tmp_path, monkeypatch):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    init_db(connection)
    seed_data(connection)
    _approval(connection)

    from guard import audit

    monkeypatch.setattr(audit, "LOG_PATH", log_path)
    observed = _registry() + [
        {
            "name": "unexpected_tool",
            "title": None,
            "description": "Synthetic unexpected tool.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"additionalProperties": True, "type": "object"},
            "annotations": None,
            "icons": None,
            "meta": None,
        }
    ]
    monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: observed)

    request = ExecutionRequest(
        request_id="REQ-SENTINEL-DRIFT",
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-SENTINEL-001",
        action=_action(),
        destination=DESTINATION,
    )
    before = connection.execute(
        "SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'"
    ).fetchone()["dose"]

    from guard import gateway
    from server import backend

    execute_calls = 0
    apply_order_calls = 0
    real_execute = gateway.execute
    real_apply = backend.apply_order

    def _spy_execute(*args, **kwargs):
        nonlocal execute_calls
        execute_calls += 1
        return real_execute(*args, **kwargs)

    def _spy_apply(*args, **kwargs):
        nonlocal apply_order_calls
        apply_order_calls += 1
        return real_apply(*args, **kwargs)

    monkeypatch.setattr(gateway, "execute", _spy_execute)
    monkeypatch.setattr(backend, "apply_order", _spy_apply)

    decision = verify_execution(request, connection, destination=DESTINATION)

    assert decision.decision == "blocked"
    assert decision.rule == "tool registry drift"
    assert decision.state_changed is False
    # Handler spy verification: protected handlers were NOT invoked
    assert execute_calls == 0
    assert apply_order_calls == 0
    assert connection.execute(
        "SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'"
    ).fetchone()["dose"] == before
    assert connection.execute(
        "SELECT consumed FROM approvals WHERE approval_id = ?",
        ("APR-SENTINEL-001",),
    ).fetchone()["consumed"] == 0
    assert connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE request_id = ?",
        ("REQ-SENTINEL-DRIFT",),
    ).fetchone()[0] == 1
    evidence = evidence_for_request("REQ-SENTINEL-DRIFT", connection=connection)
    assert evidence is not None
    assert evidence["failed_check"] == "tool registry drift"
    assert evidence["expected_fingerprint"]
    assert evidence["observed_fingerprint"]
    assert evidence["state_changed"] is False
    assert "P-104" not in json.dumps(evidence)
    connection.close()


def test_output_schema_drift_blocks_gateway_before_protected_handler(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    init_db(connection)
    seed_data(connection)
    _approval(connection, approval_id="APR-OUTPUT-SCHEMA")

    from guard import audit, gateway

    monkeypatch.setattr(audit, "LOG_PATH", log_path)
    tampered = _registry()
    tampered[0]["outputSchema"]["type"] = "array"
    monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: tampered)

    execute_calls = 0
    real_execute = gateway.execute

    def _spy_execute(*args, **kwargs):
        nonlocal execute_calls
        execute_calls += 1
        return real_execute(*args, **kwargs)

    monkeypatch.setattr(gateway, "execute", _spy_execute)
    request = ExecutionRequest(
        request_id="REQ-OUTPUT-SCHEMA",
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-OUTPUT-SCHEMA",
        action=_action(),
        destination=DESTINATION,
    )

    decision = verify_execution(request, connection, destination=DESTINATION)

    assert decision.decision == "blocked"
    assert decision.rule == "tool registry drift"
    assert execute_calls == 0
    assert connection.execute(
        "SELECT consumed FROM approvals WHERE approval_id = ?",
        ("APR-OUTPUT-SCHEMA",),
    ).fetchone()["consumed"] == 0
    assert "changed output schema: get_patient_record" in decision.reason
    connection.close()


@pytest.mark.parametrize(
    "tampering_scenario",
    [
        "missing_tool",
        "unexpected_tool",
        "malformed_schema",
        "metadata_drift",
        "inspection_error",
    ],
)
def test_all_tampering_variants_block_handler_invocation(
    tmp_path, monkeypatch, tampering_scenario
):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    init_db(connection)
    seed_data(connection)
    _approval(connection, approval_id=f"APR-{tampering_scenario}")

    from guard import audit, gateway, sentinel
    from server import backend

    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    if tampering_scenario == "missing_tool":
        monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: _registry()[1:])
    elif tampering_scenario == "unexpected_tool":
        extra = _registry() + [
            {
                "name": "injected_exfiltration_tool",
                "title": None,
                "description": "Malicious injected tool.",
                "inputSchema": {"type": "object"},
                "outputSchema": {"additionalProperties": True, "type": "object"},
                "annotations": None,
                "icons": None,
                "meta": None,
            }
        ]
        monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: extra)
    elif tampering_scenario == "malformed_schema":
        mutated = _registry()
        mutated[0]["inputSchema"] = {"properties": {"patient_id": {"type": "integer"}}}
        monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: mutated)
    elif tampering_scenario == "metadata_drift":
        mutated = _registry()
        mutated[0]["description"] = "Tampered description."
        monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: mutated)
    elif tampering_scenario == "inspection_error":
        monkeypatch.setattr(
            sentinel,
            "inspect_runtime_registry",
            lambda: (_ for _ in ()).throw(sentinel.RegistryInspectionError("unverifiable")),
        )

    execute_calls = 0
    apply_order_calls = 0

    def _spy_execute(*args, **kwargs):
        nonlocal execute_calls
        execute_calls += 1

    def _spy_apply(*args, **kwargs):
        nonlocal apply_order_calls
        apply_order_calls += 1

    monkeypatch.setattr(gateway, "execute", _spy_execute)
    monkeypatch.setattr(backend, "apply_order", _spy_apply)

    request = ExecutionRequest(
        request_id=f"REQ-{tampering_scenario}",
        actor_id="agent_1",
        tool="update_order",
        approval_id=f"APR-{tampering_scenario}",
        action=_action(),
        destination=DESTINATION,
    )

    decision = verify_execution(request, connection, destination=DESTINATION)

    assert decision.decision == "blocked"
    assert decision.state_changed is False
    assert execute_calls == 0
    assert apply_order_calls == 0

    # Assert approval was not consumed
    approval_row = connection.execute(
        "SELECT consumed FROM approvals WHERE approval_id = ?",
        (f"APR-{tampering_scenario}",),
    ).fetchone()
    assert approval_row["consumed"] == 0

    connection.close()


def test_repeated_tampering_remains_fail_closed(tmp_path, monkeypatch):
    database_path = tmp_path / "medishield.sqlite3"
    log_path = tmp_path / "logs" / "events.jsonl"
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    init_db(connection)
    seed_data(connection)
    _approval(connection, approval_id="APR-REPEATED")

    from guard import audit, gateway, sentinel
    from server import backend

    monkeypatch.setattr(audit, "LOG_PATH", log_path)

    execute_calls = 0

    def _spy_execute(*args, **kwargs):
        nonlocal execute_calls
        execute_calls += 1

    monkeypatch.setattr(gateway, "execute", _spy_execute)

    request = ExecutionRequest(
        request_id="REQ-REPEATED-1",
        actor_id="agent_1",
        tool="update_order",
        approval_id="APR-REPEATED",
        action=_action(),
        destination=DESTINATION,
    )

    # First mutation: extra tool
    monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: _registry() + [{"name": "tool_x", "title": None, "description": "x", "inputSchema": {"type": "object"}, "outputSchema": {"additionalProperties": True, "type": "object"}, "annotations": None, "icons": None, "meta": None}])
    d1 = verify_execution(request, connection, destination=DESTINATION)
    assert d1.decision == "blocked"
    assert execute_calls == 0

    # Second mutation: missing tool
    monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: _registry()[:3])
    d2 = verify_execution(request, connection, destination=DESTINATION)
    assert d2.decision == "blocked"
    assert execute_calls == 0

    # Third mutation: malformed
    monkeypatch.setattr(sentinel, "inspect_runtime_registry", lambda: "not-a-list")
    d3 = verify_execution(request, connection, destination=DESTINATION)
    assert d3.decision == "blocked"
    assert execute_calls == 0

    # Restoration: trusted registry succeeds
    monkeypatch.setattr(sentinel, "inspect_runtime_registry", _registry)
    from server.backend import execute as original_execute
    execute_calls = 0
    def _execute_passthrough(*args, **kwargs):
        nonlocal execute_calls
        execute_calls += 1
        original_execute(*args, **kwargs)
    monkeypatch.setattr(gateway, "execute", _execute_passthrough)

    d_ok = verify_execution(request, connection, destination=DESTINATION)
    assert d_ok.decision == "allowed"
    assert d_ok.state_changed is True
    assert execute_calls == 1

    connection.close()


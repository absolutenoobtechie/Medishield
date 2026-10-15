"""Focused regression tests for approval authenticity and transactions."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from guard import audit
from guard.approval import parse_approval_action
from guard.gateway import verify_execution
from guard.intent import canonicalize_action
from guard.models import ExecutionRequest, ProtectedAction
from guard.policy import PINNED_DESTINATIONS
from privacy.auth import authenticate_local
from server import backend
from server.db import get_connection, initialize_db


DESTINATION = PINNED_DESTINATIONS["update_order"]


def _action(dose: str = "5", units: str = "mg") -> ProtectedAction:
    return ProtectedAction(
        patient_id="P-104",
        medication_id="MED-A",
        dose=dose,
        units=units,
        route="oral",
        frequency="daily",
        duration="7 days",
        order_id="ORD-DEMO-001",
    )


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "medishield.sqlite3"
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "logs" / "events.jsonl")
    connection = initialize_db(path)
    yield path, connection
    connection.close()


def _request(approval_id: str, request_id: str, action: ProtectedAction) -> ExecutionRequest:
    return ExecutionRequest(
        request_id=request_id,
        actor_id="agent_1",
        tool="update_order",
        approval_id=approval_id,
        action=action,
        destination=DESTINATION,
    )


def test_tampered_approval_record_is_rejected_without_consumption(database):
    _, connection = database
    approval_id = backend.create_approval(
        _action(),
        "clinician_1",
        5,
        connection,
        trusted_user=authenticate_local(connection, "clinician_1", "ORG-DEMO"),
    )
    connection.commit()
    connection.execute(
        "UPDATE approvals SET expires_at = ? WHERE approval_id = ?",
        ("2026-10-15T00:00:00Z", approval_id),
    )
    connection.commit()

    decision = verify_execution(
        _request(approval_id, "REQ-TAMPERED-APPROVAL", _action()),
        connection,
        destination=DESTINATION,
    )

    assert decision.decision == "blocked"
    assert decision.rule == "approval authentication failed"
    assert connection.execute(
        "SELECT consumed FROM approvals WHERE approval_id = ?", (approval_id,)
    ).fetchone()[0] == 0


def test_missing_secret_blocks_execution_without_state_change(database, monkeypatch):
    _, connection = database
    approval_id = backend.create_approval(
        _action(),
        "clinician_1",
        5,
        connection,
        trusted_user=authenticate_local(connection, "clinician_1", "ORG-DEMO"),
    )
    connection.commit()
    before = connection.execute(
        "SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'"
    ).fetchone()[0]
    monkeypatch.delenv("MEDISHIELD_APPROVAL_SECRET", raising=False)

    decision = verify_execution(
        _request(approval_id, "REQ-MISSING-SECRET", _action()),
        connection,
        destination=DESTINATION,
    )

    assert decision.decision == "blocked"
    assert decision.rule == "approval authentication unavailable"
    assert connection.execute(
        "SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'"
    ).fetchone()[0] == before
    assert connection.execute(
        "SELECT consumed FROM approvals WHERE approval_id = ?", (approval_id,)
    ).fetchone()[0] == 0


def test_canonicalization_is_strict_and_decimal_deterministic():
    assert canonicalize_action(_action("5.00", "MILLIGRAMS")) == canonicalize_action(
        _action("5", "mg")
    )
    with pytest.raises(ValueError):
        canonicalize_action(_action("5", "unknown-unit"))
    with pytest.raises(ValueError):
        canonicalize_action(_action("1e-200", "mg"))

    canonical = canonicalize_action(_action())
    duplicate = canonical[:-1] + ',"dose":"6"}'
    with pytest.raises(ValueError):
        parse_approval_action(duplicate)


def test_gateway_does_not_commit_callers_transaction(database):
    _, connection = database
    approval_id = backend.create_approval(
        _action(),
        "clinician_1",
        5,
        connection,
        trusted_user=authenticate_local(connection, "clinician_1", "ORG-DEMO"),
    )
    connection.execute(
        "UPDATE orders SET dose = ? WHERE order_id = ?",
        ("caller-uncommitted", "ORD-DEMO-001"),
    )
    decision = verify_execution(
        _request(approval_id, "REQ-CALLER-TX", _action()),
        connection,
        destination=DESTINATION,
    )

    assert decision.decision == "allowed"
    connection.rollback()
    assert connection.execute(
        "SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'"
    ).fetchone()[0] == "SIMULATED-5"
    assert connection.execute(
        "SELECT COUNT(*) FROM approvals WHERE approval_id = ?", (approval_id,)
    ).fetchone()[0] == 0


def test_single_use_approval_allows_only_one_concurrent_request(database):
    path, connection = database
    approval_id = backend.create_approval(
        _action(),
        "clinician_1",
        5,
        connection,
        trusted_user=authenticate_local(connection, "clinician_1", "ORG-DEMO"),
    )
    connection.commit()
    barrier = Barrier(2)

    def execute_once(index: int):
        worker_connection = get_connection(path)
        try:
            barrier.wait(timeout=5)
            return verify_execution(
                _request(approval_id, f"REQ-CONCURRENT-{index}", _action()),
                worker_connection,
                destination=DESTINATION,
            )
        finally:
            worker_connection.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        decisions = list(pool.map(execute_once, (1, 2)))

    assert sorted(decision.decision for decision in decisions) == ["allowed", "blocked"]
    assert connection.execute(
        "SELECT consumed FROM approvals WHERE approval_id = ?", (approval_id,)
    ).fetchone()[0] == 1

"""FastMCP tools for the synthetic MediShield clinical backend."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from mcp.server.fastmcp import FastMCP

from guard.gateway import verify_execution
from guard.models import Decision, ExecutionRequest, ProtectedAction
from guard.policy import PINNED_DESTINATIONS
from server import backend
from server.db import DEFAULT_DB_PATH, get_connection, init_db, initialize_db


DATABASE_PATH = DEFAULT_DB_PATH
UPDATE_ORDER_TOOL = "update_order"

mcp = FastMCP("MediShield")


def _model_dump(model: Any) -> dict[str, Any]:
    """Support both Pydantic versions allowed by the project."""

    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _action(action: ProtectedAction | dict[str, Any]) -> ProtectedAction:
    """Validate a tool action using the shared strict contract."""

    if isinstance(action, ProtectedAction):
        return action
    if isinstance(action, dict):
        if hasattr(ProtectedAction, "model_validate"):
            return ProtectedAction.model_validate(action)
        return ProtectedAction.parse_obj(action)
    raise TypeError("action must be a ProtectedAction or object")


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert one configured SQLite row to a JSON-ready dictionary."""

    return {key: row[key] for key in row.keys()}


@mcp.tool()
def get_patient_record(patient_id: str) -> dict[str, Any]:
    """Return one synthetic patient and that patient's synthetic orders."""

    connection = initialize_db(DATABASE_PATH)
    try:
        patient = connection.execute(
            "SELECT patient_id, name_synthetic FROM patients WHERE patient_id = ?",
            (patient_id,),
        ).fetchone()
        if patient is None:
            raise ValueError(f"Unknown synthetic patient: {patient_id}")

        orders = connection.execute(
            """
            SELECT order_id, patient_id, medication_id, dose, units,
                   route, frequency, duration
            FROM orders
            WHERE patient_id = ?
            ORDER BY order_id
            """,
            (patient_id,),
        ).fetchall()
        return {
            "patient": _row_dict(patient),
            "orders": [_row_dict(order) for order in orders],
        }
    finally:
        connection.close()


@mcp.tool()
def propose_medication_order(action: ProtectedAction) -> dict[str, Any]:
    """Validate and return a medication-order proposal without changing state."""

    validated_action = _action(action)
    return {"status": "proposed", "action": _model_dump(validated_action)}


@mcp.tool()
def request_clinician_approval(
    action: ProtectedAction,
    approver_id: str,
    ttl_minutes: float,
) -> dict[str, Any]:
    """Create a clinician approval for the exact validated protected action."""

    validated_action = _action(action)
    approval_id = backend.create_approval(
        validated_action,
        approver_id,
        ttl_minutes,
    )
    return {
        "approval_id": approval_id,
        "approver_id": approver_id,
        "status": "pending",
    }


@mcp.tool()
def execute_approved_order(
    request_id: str,
    actor_id: str,
    approval_id: str,
    action: ProtectedAction,
) -> dict[str, Any]:
    """Ask the security gateway to verify and execute one approved order.

    This tool constructs the execution request and delegates all protected
    execution to ``verify_execution``. It never calls the backend directly.
    """

    validated_action = _action(action)
    request = ExecutionRequest(
        request_id=request_id,
        actor_id=actor_id,
        tool=UPDATE_ORDER_TOOL,
        approval_id=approval_id,
        action=validated_action,
    )
    decision: Decision = verify_execution(
        request,
        destination=PINNED_DESTINATIONS[UPDATE_ORDER_TOOL],
    )
    return _model_dump(decision)


@mcp.tool()
def get_security_events(limit: int = 20) -> list[dict[str, Any]]:
    """Return the newest synthetic security audit events."""

    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit must be a positive integer")

    connection = get_connection(DATABASE_PATH)
    try:
        init_db(connection)
        rows = connection.execute(
            """
            SELECT id, time, request_id, actor_id, tool, action_type,
                   approval_id, decision, risk, rule, reason,
                   changed_fields, state_changed
            FROM audit_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        events = []
        for row in rows:
            event = _row_dict(row)
            event["actor"] = event.pop("actor_id")
            event["changed_fields"] = json.loads(event["changed_fields"])
            event["state_changed"] = bool(event["state_changed"])
            event.pop("id")
            events.append(event)
        return events
    finally:
        connection.close()


if __name__ == "__main__":
    mcp.run(transport="stdio")

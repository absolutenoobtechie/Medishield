"""Simulated clinical backend boundary for MediShield demo."""

import sqlite3
from typing import Optional

from guard.models import ExecutionRequest
from server.db import DEFAULT_DB_PATH, get_connection


def execute(request: ExecutionRequest, connection: Optional[sqlite3.Connection] = None) -> None:
    """Execute a validated synthetic clinical backend action.

    This updates the orders table in the simulated database for the approved action.
    """
    close_after = False
    if connection is None:
        connection = get_connection(DEFAULT_DB_PATH)
        close_after = True

    try:
        action = request.action
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO orders (order_id, patient_id, medication_id, dose, units, route, frequency, duration)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(order_id) DO UPDATE SET
                patient_id = excluded.patient_id,
                medication_id = excluded.medication_id,
                dose = excluded.dose,
                units = excluded.units,
                route = excluded.route,
                frequency = excluded.frequency,
                duration = excluded.duration
            """,
            (
                action.order_id,
                action.patient_id,
                action.medication_id,
                action.dose,
                action.units,
                action.route,
                action.frequency,
                action.duration,
            ),
        )
        connection.commit()
    finally:
        if close_after:
            connection.close()

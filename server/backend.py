"""Synthetic clinical backend operations used by the gateway."""

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Iterator, Optional

from guard.intent import action_hash, canonicalize_action
from guard.models import ProtectedAction

from .db import DEFAULT_DB_PATH, PathLike, get_connection, init_db, initialize_db


DATABASE_PATH: PathLike = DEFAULT_DB_PATH


@contextmanager
def _connection_scope(
    connection: Optional[sqlite3.Connection],
    seed: bool = True,
) -> Iterator[tuple[sqlite3.Connection, bool]]:
    """Yield a connection and whether this module owns its lifecycle."""

    owned = connection is None
    if owned:
        current = initialize_db(DATABASE_PATH) if seed else get_connection(DATABASE_PATH)
        if not seed:
            init_db(current)
    else:
        current = connection
    try:
        yield current, owned
    except Exception:
        if owned:
            current.rollback()
        raise
    finally:
        if owned:
            current.close()


def _as_action(action: ProtectedAction | dict) -> ProtectedAction:
    """Validate and normalize an action without changing its protected fields."""

    if isinstance(action, ProtectedAction):
        return action
    if isinstance(action, dict):
        return ProtectedAction.parse_obj(action)
    raise TypeError("action must be a ProtectedAction or a dictionary")


def _positive_ttl(ttl_minutes: object) -> Decimal:
    """Return a finite positive TTL as Decimal or raise ValueError."""

    if isinstance(ttl_minutes, bool):
        raise ValueError("ttl_minutes must be a positive number")
    try:
        ttl = Decimal(str(ttl_minutes))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("ttl_minutes must be a positive number") from None
    if not ttl.is_finite() or ttl <= 0:
        raise ValueError("ttl_minutes must be a positive number")
    return ttl


def _utc_timestamp(value: datetime) -> str:
    """Serialize an aware UTC datetime consistently for SQLite."""

    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def create_approval(
    action: ProtectedAction | dict,
    approver_id: str,
    ttl_minutes: object,
    connection: Optional[sqlite3.Connection] = None,
) -> str:
    """Create one clinician approval and return its generated ID.

    ``action_hash`` is always recomputed from the validated action. With an
    injected connection, the caller owns the transaction and this function
    does not commit. Without one, it initializes the configured synthetic
    database and commits only after the approval row is inserted.
    """

    ttl = _positive_ttl(ttl_minutes)

    with _connection_scope(connection) as (current, owns_connection):
        actor = current.execute(
            "SELECT role FROM actors WHERE actor_id = ?",
            (approver_id,),
        ).fetchone()
        if actor is None:
            raise ValueError(f"Unknown approver: {approver_id}")
        role = actor["role"] if isinstance(actor, sqlite3.Row) else actor[0]
        if role != "clinician":
            raise PermissionError("Only a clinician can create an approval")

        validated_action = _as_action(action)
        action_json = canonicalize_action(validated_action)
        digest = action_hash(validated_action)
        if not isinstance(action_json, str) or not isinstance(digest, str):
            raise TypeError("intent functions must return strings")

        now = datetime.now(timezone.utc)
        try:
            expires = now + timedelta(seconds=float(ttl * Decimal("60")))
        except (OverflowError, ValueError):
            raise ValueError("ttl_minutes is too large") from None
        approval_id = f"APR-{uuid.uuid4().hex}"

        current.execute(
            """
            INSERT INTO approvals(
                approval_id, action_hash, action_json, approver_id,
                created_at, expires_at, revoked, consumed
            ) VALUES (?, ?, ?, ?, ?, ?, 0, 0)
            """,
            (
                approval_id,
                digest,
                action_json,
                approver_id,
                _utc_timestamp(now),
                _utc_timestamp(expires),
            ),
        )
        if owns_connection:
            current.commit()

    return approval_id


def revoke_approval(
    approval_id: str,
    connection: Optional[sqlite3.Connection] = None,
) -> None:
    """Mark an existing approval revoked without deleting its audit history."""

    with _connection_scope(connection) as (current, owns_connection):
        result = current.execute(
            "UPDATE approvals SET revoked = 1 WHERE approval_id = ?",
            (approval_id,),
        )
        if result.rowcount != 1:
            raise LookupError(f"Unknown approval: {approval_id}")
        if owns_connection:
            current.commit()


def get_state(
    connection: Optional[sqlite3.Connection] = None,
) -> dict[str, list[dict[str, object]]]:
    """Return ``{'orders': [...]}`` in deterministic order without writing state."""

    with _connection_scope(connection, seed=False) as (current, _):
        rows = current.execute(
            """
            SELECT order_id, patient_id, medication_id, dose, units,
                   route, frequency, duration
            FROM orders
            ORDER BY order_id
            """
        ).fetchall()
        columns = (
            "order_id",
            "patient_id",
            "medication_id",
            "dose",
            "units",
            "route",
            "frequency",
            "duration",
        )
        orders = [
            dict(row)
            if isinstance(row, sqlite3.Row)
            else dict(zip(columns, row))
            for row in rows
        ]
        return {"orders": orders}


# SECURITY: Call only from guard/gateway.py inside its transaction.
def apply_order(
    action: ProtectedAction | dict,
    connection: Optional[sqlite3.Connection] = None,
) -> None:
    """Insert or update one synthetic order using the caller's transaction.

    A caller-owned connection is required. This function never commits,
    starts a transaction, or catches database errors, so the gateway can
    roll back the order if a later operation fails.
    """

    if connection is None:
        raise RuntimeError("apply_order requires the gateway transaction connection")

    validated_action = _as_action(action)
    connection.execute(
        """
        INSERT INTO orders(
            order_id, patient_id, medication_id, dose, units,
            route, frequency, duration
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
            validated_action.order_id,
            validated_action.patient_id,
            validated_action.medication_id,
            validated_action.dose,
            validated_action.units,
            validated_action.route,
            validated_action.frequency,
            validated_action.duration,
        ),
    )

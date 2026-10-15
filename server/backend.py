"""Synthetic clinical backend operations used by the gateway."""

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Iterator, Optional

from guard.approval import compute_approval_mac
from guard.intent import action_hash, canonicalize_action
from guard.models import ProtectedAction
from privacy.auth import AuthorizationError, WorkspaceUser, require_permission

from .db import DEFAULT_DB_PATH, PathLike, get_connection, init_db, initialize_db


DATABASE_PATH: PathLike = DEFAULT_DB_PATH
_GATEWAY_EXECUTION_TOKEN = object()


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
        if hasattr(ProtectedAction, "model_validate"):
            return ProtectedAction.model_validate(action)
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
    *,
    trusted_user: WorkspaceUser | None = None,
) -> str:
    """Create one clinician approval and return its generated ID.

    ``action_hash`` is always recomputed from the validated action. With an
    injected connection, the caller owns the transaction and this function
    does not commit. Without one, it initializes the configured synthetic
    database and commits only after the approval row is inserted.
    """

    ttl = _positive_ttl(ttl_minutes)

    with _connection_scope(connection) as (current, owns_connection):
        if trusted_user is None:
            raise PermissionError(
                "Approval creation requires a server-authenticated clinician context"
            )
        try:
            current_user = require_permission(current, trusted_user, "approval_confirm")
        except AuthorizationError as exc:
            raise PermissionError("Only an authenticated clinician can create an approval") from exc
        if approver_id != current_user.actor_id:
            raise PermissionError("The approver must match the authenticated clinician")

        validated_action = _as_action(action)
        patient = current.execute(
            "SELECT org_id FROM patients WHERE patient_id = ?",
            (validated_action.patient_id,),
        ).fetchone()
        if patient is None or patient["org_id"] != current_user.org_id:
            raise PermissionError(
                "The approval action is outside the authenticated organization"
            )
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
        created_at = _utc_timestamp(now)
        expires_at = _utc_timestamp(expires)
        approval_mac = compute_approval_mac(
            approval_id=approval_id,
            action_json=action_json,
            action_hash=digest,
            approver_id=approver_id,
            created_at=created_at,
            expires_at=expires_at,
        )

        current.execute(
            """
            INSERT INTO approvals(
                approval_id, action_hash, action_json, approver_id,
                created_at, expires_at, revoked, consumed, approval_mac
            ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
            """,
            (
                approval_id,
                digest,
                action_json,
                approver_id,
                created_at,
                expires_at,
                approval_mac,
            ),
        )
        from guard.audit import record_audit_event

        record_audit_event(
            {
                "time": created_at,
                "request_id": f"approval:{approval_id}",
                "actor": approver_id,
                "tool": "approval_store",
                "action_type": "approval_created",
                "approval_id": approval_id,
                "decision": "allowed",
                "risk": "low",
                "rule": "clinician approval created",
                "reason": "A clinician created a time-limited authenticated approval.",
                "changed_fields": [],
                "state_changed": False,
            },
            current,
        )
        if owns_connection:
            current.commit()

    return approval_id


def revoke_approval(
    approval_id: str,
    connection: Optional[sqlite3.Connection] = None,
    *,
    trusted_user: WorkspaceUser | None = None,
) -> None:
    """Mark an existing approval revoked without deleting its audit history."""

    with _connection_scope(connection) as (current, owns_connection):
        if trusted_user is None:
            raise PermissionError(
                "Approval revocation requires a server-authenticated clinician context"
            )
        try:
            require_permission(current, trusted_user, "approval_confirm")
        except AuthorizationError as exc:
            raise PermissionError("Only an authenticated clinician can revoke an approval") from exc
        result = current.execute(
            "UPDATE approvals SET revoked = 1 WHERE approval_id = ?",
            (approval_id,),
        )
        if result.rowcount != 1:
            raise LookupError(f"Unknown approval: {approval_id}")
        from guard.audit import record_audit_event

        record_audit_event(
            {
                "time": _utc_timestamp(datetime.now(timezone.utc)),
                "request_id": f"approval:{approval_id}:revoked",
                "actor": "system",
                "tool": "approval_store",
                "action_type": "approval_revoked",
                "approval_id": approval_id,
                "decision": "allowed",
                "risk": "low",
                "rule": "approval revoked",
                "reason": "The trusted backend marked the approval revoked.",
                "changed_fields": ["revoked"],
                "state_changed": False,
            },
            current,
        )
        if owns_connection:
            current.commit()


def get_state(
    connection: Optional[sqlite3.Connection] = None,
    *,
    trusted_user: WorkspaceUser | None = None,
) -> dict[str, list[dict[str, object]]]:
    """Return ``{'orders': [...]}`` in deterministic order without writing state."""

    with _connection_scope(connection, seed=False) as (current, _):
        if trusted_user is None:
            raise PermissionError(
                "Reading order state requires a server-authenticated context"
            )
        try:
            current_user = require_permission(current, trusted_user, "patient_read")
        except AuthorizationError as exc:
            raise PermissionError("Order-state access is not authorized") from exc
        rows = current.execute(
            """
            SELECT order_id, patient_id, medication_id, dose, units,
                   route, frequency, duration
            FROM orders
            JOIN patients ON patients.patient_id = orders.patient_id
            WHERE patients.org_id = ?
            ORDER BY order_id
            """,
            (current_user.org_id,),
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


def get_patient_record(
    patient_id: str,
    connection: Optional[sqlite3.Connection] = None,
    *,
    trusted_user: WorkspaceUser | None = None,
) -> dict[str, Any]:
    """Retrieve one synthetic patient record and associated orders.

    Protected clinical backend handler. Returns patient demographics and
    current active orders.
    """

    with _connection_scope(connection, seed=True) as (current, _):
        if trusted_user is None:
            raise PermissionError(
                "Patient-record access requires a server-authenticated context"
            )
        try:
            current_user = require_permission(current, trusted_user, "patient_read")
        except AuthorizationError as exc:
            raise PermissionError("Patient-record access is not authorized") from exc
        patient = current.execute(
            "SELECT patient_id, name_synthetic, org_id FROM patients WHERE patient_id = ?",
            (patient_id,),
        ).fetchone()
        if patient is None:
            raise ValueError(f"Unknown synthetic patient: {patient_id}")
        if patient["org_id"] != current_user.org_id:
            raise PermissionError("Patient-record access is outside the authenticated organization")

        orders = current.execute(
            """
            SELECT order_id, patient_id, medication_id, dose, units,
                   route, frequency, duration
            FROM orders
            WHERE patient_id = ?
            ORDER BY order_id
            """,
            (patient_id,),
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
        patient_dict = (
            dict(patient)
            if isinstance(patient, sqlite3.Row)
            else {"patient_id": patient[0], "name_synthetic": patient[1]}
        )
        order_dicts = [
            dict(order)
            if isinstance(order, sqlite3.Row)
            else dict(zip(columns, order))
            for order in orders
        ]
        return {
            "patient": patient_dict,
            "orders": order_dicts,
        }


# SECURITY: Call only from guard/gateway.py inside its transaction.
def apply_order(
    action: ProtectedAction | dict,
    connection: Optional[sqlite3.Connection] = None,
    *,
    _gateway_token: object = None,
) -> None:
    """Insert or update one synthetic order using the caller's transaction.

    A caller-owned connection is required. This function never commits,
    starts a transaction, or catches database errors, so the gateway can
    roll back the order if a later operation fails.
    """

    if connection is None:
        raise RuntimeError("apply_order requires the gateway transaction connection")
    if _gateway_token is not _GATEWAY_EXECUTION_TOKEN:
        raise PermissionError("order writes are restricted to the security gateway")

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



def execute(
    request,
    connection: Optional[sqlite3.Connection] = None,
    *,
    _gateway_token: object = None,
) -> None:
    """Compatibility entry point used by the security gateway.

    The gateway supplies its transaction connection so approval consumption,
    order mutation, and audit persistence can commit or roll back together.
    Direct callers cannot use this compatibility helper as a second execution
    path; only the gateway's private capability token is accepted.
    """

    if _gateway_token is not _GATEWAY_EXECUTION_TOKEN:
        raise PermissionError("backend execution is restricted to the security gateway")

    close_after = connection is None
    current = connection if connection is not None else get_connection(DATABASE_PATH)
    try:
        if not hasattr(request, "action"):
            raise TypeError("request must expose a validated action")
        apply_order(
            request.action,
            connection=current,
            _gateway_token=_GATEWAY_EXECUTION_TOKEN,
        )
        if close_after:
            current.commit()
    except Exception:
        if close_after:
            current.rollback()
        raise
    finally:
        if close_after:
            current.close()

"""Tenant-scoped authorization for the local synthetic workspace."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass


class AuthorizationError(PermissionError):
    """Raised when an actor has no active membership for a tenant/action."""


@dataclass(frozen=True)
class WorkspaceUser:
    actor_id: str
    org_id: str
    role: str


def authenticate_local(connection: sqlite3.Connection, actor_id: str, org_id: str) -> WorkspaceUser:
    """Resolve a seeded local-demo membership; this is not production login."""

    row = connection.execute(
        """
        SELECT a.actor_id, m.org_id, m.role
        FROM memberships AS m
        JOIN actors AS a ON a.actor_id = m.actor_id
        WHERE m.actor_id = ? AND m.org_id = ? AND m.active = 1
        """,
        (actor_id, org_id),
    ).fetchone()
    if row is None:
        raise AuthorizationError("actor is not an active member of this organization")
    return WorkspaceUser(actor_id=row[0], org_id=row[1], role=row[2])


def require_permission(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    permission: str,
) -> WorkspaceUser:
    """Re-read membership from SQLite before every protected vault operation."""

    current = authenticate_local(connection, user.actor_id, user.org_id)
    allowed: dict[str, set[str]] = {
        "upload": {"org_admin", "clinician", "privacy_officer"},
        "review": {"org_admin", "privacy_officer"},
        "metadata": {"org_admin", "clinician", "privacy_officer", "researcher", "read_only_auditor"},
        "retrieve_derivative": {"org_admin", "clinician", "privacy_officer", "researcher"},
        "retrieve_original": {"org_admin", "clinician", "privacy_officer"},
        "delete": {"org_admin"},
        "patient_read": {"org_admin", "clinician", "privacy_officer"},
        "security_events": {"org_admin", "privacy_officer", "read_only_auditor"},
        "approval_confirm": {"clinician"},
        "clinical_execute": {"agent", "clinician"},
    }
    if current.role not in allowed.get(permission, set()):
        raise AuthorizationError(f"role {current.role!r} is not permitted to {permission}")
    return current

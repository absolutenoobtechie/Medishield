"""Audit trail management for MediShield gateway outcomes."""

from datetime import datetime, timezone
import json
import sqlite3
from typing import Any, Dict, Optional, Union

from server.db import DEFAULT_DB_PATH, get_connection


def record_audit_event(
    event: Dict[str, Any],
    connection: Optional[sqlite3.Connection] = None,
    db_path: Union[str, Any] = DEFAULT_DB_PATH,
) -> int:
    """Persist an audit event into the SQLite audit_events table.
    
    Guarantees every outcome (allowed, blocked, warning) is securely audited.
    """
    close_after = False
    if connection is None:
        connection = get_connection(db_path)
        close_after = True

    try:
        # Normalize fields
        time_str = event.get("time") or datetime.now(timezone.utc).isoformat()
        request_id = str(event.get("request_id", ""))
        actor_id = str(event.get("actor") or event.get("actor_id", "unknown"))
        tool = str(event.get("tool", "unknown"))
        action_type = str(event.get("action_type", "unknown"))
        approval_id = event.get("approval_id")
        decision = str(event.get("decision", "blocked"))
        risk = str(event.get("risk", "medium"))
        rule = str(event.get("rule", "unknown"))
        reason = str(event.get("reason", ""))
        
        changed_fields = event.get("changed_fields", [])
        if isinstance(changed_fields, (list, tuple, set)):
            cf_str = json.dumps(list(changed_fields))
        else:
            cf_str = str(changed_fields)

        state_changed = 1 if event.get("state_changed") else 0

        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO audit_events (
                time, request_id, actor_id, tool, action_type, approval_id,
                decision, risk, rule, reason, changed_fields, state_changed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time_str,
                request_id,
                actor_id,
                tool,
                action_type,
                approval_id,
                decision,
                risk,
                rule,
                reason,
                cf_str,
                state_changed,
            ),
        )
        connection.commit()
        return cursor.lastrowid or 0
    finally:
        if close_after:
            connection.close()

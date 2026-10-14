"""Audit event persistence for the synthetic MediShield gateway."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional

from server.db import DEFAULT_DB_PATH, PathLike, get_connection, init_db


DATABASE_PATH: PathLike = DEFAULT_DB_PATH
LOG_PATH = Path("logs/events.jsonl")
AUDIT_FIELDS = (
    "time",
    "request_id",
    "actor",
    "tool",
    "action_type",
    "approval_id",
    "decision",
    "risk",
    "rule",
    "reason",
    "changed_fields",
    "state_changed",
)


def _utc_time(value: object) -> str:
    """Validate and normalize an event timestamp to UTC with a Z suffix."""

    if value is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if not isinstance(value, str):
        raise TypeError("event time must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("event time must be valid ISO-8601") from None
    if parsed.tzinfo is None:
        raise ValueError("event time must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_event(event: Mapping[str, object]) -> dict[str, object]:
    """Validate the contract and return JSON-serializable event data."""

    unknown = set(event) - set(AUDIT_FIELDS)
    if unknown:
        raise ValueError(f"Unknown audit event fields: {sorted(unknown)}")

    missing = [field for field in AUDIT_FIELDS if field not in event]
    if "time" in missing:
        missing.remove("time")
    if missing:
        raise ValueError(f"Missing audit event fields: {missing}")

    changed_fields = event["changed_fields"]
    if not isinstance(changed_fields, list) or not all(
        isinstance(field, str) for field in changed_fields
    ):
        raise TypeError("changed_fields must be a list of strings")
    if event["decision"] not in {"allowed", "blocked", "warning"}:
        raise ValueError("decision must be allowed, blocked, or warning")
    if event["risk"] not in {"low", "medium", "high"}:
        raise ValueError("risk must be low, medium, or high")
    if not isinstance(event["state_changed"], bool):
        raise TypeError("state_changed must be a boolean")

    required_strings = (
        "request_id",
        "actor",
        "tool",
        "action_type",
        "rule",
        "reason",
    )
    for field in required_strings:
        if not isinstance(event[field], str):
            raise TypeError(f"{field} must be a string")
    if event["approval_id"] is not None and not isinstance(event["approval_id"], str):
        raise TypeError("approval_id must be a string or null")

    return {
        "time": _utc_time(event.get("time")),
        "request_id": event["request_id"],
        "actor": event["actor"],
        "tool": event["tool"],
        "action_type": event["action_type"],
        "approval_id": event["approval_id"],
        "decision": event["decision"],
        "risk": event["risk"],
        "rule": event["rule"],
        "reason": event["reason"],
        "changed_fields": changed_fields,
        "state_changed": event["state_changed"],
    }


def _append_jsonl(event: Mapping[str, object], path: Path) -> None:
    """Append exactly one valid JSON object and propagate filesystem errors."""

    path.parent.mkdir(parents=True, exist_ok=True)
    record = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(record)
        handle.write("\n")


def write_event(
    event: Mapping[str, object],
    connection: Optional[sqlite3.Connection] = None,
    log_path: Optional[PathLike] = None,
    db_path: Optional[PathLike] = None,
) -> int:
    """Store one contract event in SQLite and append the matching JSONL line.

    If ``connection`` is supplied, it remains in the caller's transaction and
    this function does not commit. If the function opens its own connection,
    it commits only after the file append succeeds. SQLite and filesystem
    writes are not fully atomic: a commit failure after a successful append can
    leave a JSONL line without a database row, and that error is propagated.
    """

    normalized = _normalize_event(event)
    path = Path(log_path) if log_path is not None else LOG_PATH
    owns_connection = connection is None
    if owns_connection:
        current = get_connection(db_path if db_path is not None else DATABASE_PATH)
        init_db(current)
    else:
        current = connection
    try:
        cursor = current.execute(
            """
            INSERT INTO audit_events(
                time, request_id, actor_id, tool, action_type, approval_id,
                decision, risk, rule, reason, changed_fields, state_changed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                normalized["time"],
                normalized["request_id"],
                normalized["actor"],
                normalized["tool"],
                normalized["action_type"],
                normalized["approval_id"],
                normalized["decision"],
                normalized["risk"],
                normalized["rule"],
                normalized["reason"],
                json.dumps(normalized["changed_fields"], separators=(",", ":")),
                int(normalized["state_changed"]),
            ),
        )
        _append_jsonl(normalized, path)
        if owns_connection:
            current.commit()
        return int(cursor.lastrowid or 0)
    except Exception:
        if owns_connection:
            current.rollback()
        raise
    finally:
        if owns_connection:
            current.close()



def record_audit_event(
    event: Mapping[str, object],
    connection: Optional[sqlite3.Connection] = None,
    db_path: Optional[PathLike] = None,
) -> int:
    """Backward-compatible gateway API for persisting an audit event.

    Existing gateway code calls this function with a caller-owned connection.
    That connection remains in the gateway's transaction; this function never
    commits it. Events are also written to the JSONL audit log.
    """
    normalized = dict(event)
    normalized.setdefault("time", None)
    normalized.setdefault("request_id", "")
    normalized.setdefault("actor", normalized.get("actor_id", "unknown"))
    normalized.setdefault("tool", "unknown")
    normalized.setdefault("action_type", normalized.get("tool", "unknown"))
    normalized.setdefault("approval_id", None)
    normalized.setdefault("decision", "blocked")
    normalized.setdefault("risk", "medium")
    normalized.setdefault("rule", "unknown")
    normalized.setdefault("reason", "")
    normalized.setdefault("changed_fields", [])
    normalized.setdefault("state_changed", False)
    return write_event(
        normalized,
        connection=connection,
        log_path=LOG_PATH,
        db_path=db_path,
    )

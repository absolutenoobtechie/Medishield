"""Audit event persistence for the synthetic MediShield gateway."""

import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from server.db import DEFAULT_DB_PATH, PathLike, get_connection, init_db


DATABASE_PATH: PathLike = DEFAULT_DB_PATH
LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "events.jsonl"
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
    except (OSError, sqlite3.Error, TypeError, ValueError):
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
    actor_id = normalized.pop("actor_id", None)
    if "actor" not in normalized or normalized["actor"] is None:
        normalized["actor"] = actor_id if actor_id is not None else "unknown"
    normalized.setdefault("tool", "unknown")
    normalized.setdefault("action_type", normalized.get("tool", "unknown"))
    normalized.setdefault("approval_id", None)
    normalized.setdefault("decision", "blocked")
    normalized.setdefault("risk", "medium")
    normalized.setdefault("rule", "unknown")
    normalized.setdefault("reason", "")
    raw_changed_fields = normalized.get("changed_fields", [])
    normalized["changed_fields"] = (
        list(raw_changed_fields)
        if isinstance(raw_changed_fields, (list, tuple, set))
        else []
    )
    normalized["state_changed"] = bool(normalized.get("state_changed", False))
    normalized = {field: normalized[field] for field in AUDIT_FIELDS}
    return write_event(
        normalized,
        connection=connection,
        log_path=LOG_PATH,
        db_path=db_path,
    )


def canonical_event_json(event: Mapping[str, Any]) -> str:
    """Return deterministic compact JSON for one audit event."""

    normalized = _normalize_event(event)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_event_digest(event: Mapping[str, Any]) -> str:
    """Return SHA-256 digest of one canonically serialized audit event."""

    return hashlib.sha256(canonical_event_json(event).encode("utf-8")).hexdigest()


def compute_audit_chain_hash(
    events: Sequence[Mapping[str, Any]],
    seed: str = "0" * 64,
) -> str:
    """Compute sequential cryptographic hash chain over an ordered sequence of events."""

    current_hash = seed
    for event in events:
        event_digest = compute_event_digest(event)
        current_hash = hashlib.sha256(
            f"{current_hash}:{event_digest}".encode("utf-8")
        ).hexdigest()
    return current_hash


def verify_audit_log_integrity(
    records: Optional[Sequence[Mapping[str, Any]]] = None,
    log_path: Optional[PathLike] = None,
    connection: Optional[sqlite3.Connection] = None,
    db_path: Optional[PathLike] = None,
    expected_chain_digest: Optional[str] = None,
) -> dict[str, Any]:
    """Verify integrity of the audit trail (modification, deletion, reordering).

    Detects:
    - Modifications: field values changed or invalid.
    - Deletions: sequence ID gaps in SQLite or record count mismatches.
    - Reordering: timestamp regressions or sequence ID inversions.
    - Cross-store divergence: differences between JSONL and SQLite events.
    """

    errors: list[str] = []
    tampering_detected = False
    tampering_type: Optional[str] = None

    file_records: list[dict[str, Any]] = []
    target_log_path = Path(log_path) if log_path is not None else (LOG_PATH if records is None and connection is None else None)
    file_store_expected = log_path is not None or (records is None and connection is None)
    file_store_exists = target_log_path.exists() if target_log_path is not None else False
    if records is not None:
        file_records = [dict(r) for r in records]
    elif target_log_path is not None and file_store_exists:
        try:
            with target_log_path.open(encoding="utf-8") as handle:
                file_records = [json.loads(line) for line in handle if line.strip()]
        except Exception as exc:
            errors.append(f"Failed to read audit log file: {exc}")
            tampering_detected = True
            tampering_type = "modification"

    db_records: list[dict[str, Any]] = []
    owns_connection = False
    db_conn = connection
    if db_conn is None and db_path is not None:
        db_path_obj = Path(db_path)
        if db_path_obj.exists():
            db_conn = get_connection(db_path_obj)
            owns_connection = True
    elif db_conn is None and records is None and target_log_path is None:
        default_db = Path(DATABASE_PATH)
        if default_db.exists():
            db_conn = get_connection(default_db)
            owns_connection = True

    db_ids: list[int] = []
    if db_conn is not None:
        try:
            cursor = db_conn.execute(
                """
                SELECT id, time, request_id, actor_id, tool, action_type,
                       approval_id, decision, risk, rule, reason,
                       changed_fields, state_changed
                FROM audit_events
                ORDER BY id ASC
                """
            )
            rows = cursor.fetchall()
            for row in rows:
                row_dict = dict(row) if isinstance(row, sqlite3.Row) else dict(zip([c[0] for c in cursor.description], row))
                db_ids.append(row_dict["id"])
                evt = {
                    "time": row_dict["time"],
                    "request_id": row_dict["request_id"],
                    "actor": row_dict["actor_id"],
                    "tool": row_dict["tool"],
                    "action_type": row_dict["action_type"],
                    "approval_id": row_dict["approval_id"],
                    "decision": row_dict["decision"],
                    "risk": row_dict["risk"],
                    "rule": row_dict["rule"],
                    "reason": row_dict["reason"],
                    "changed_fields": json.loads(row_dict["changed_fields"]) if isinstance(row_dict["changed_fields"], str) else row_dict["changed_fields"],
                    "state_changed": bool(row_dict["state_changed"]),
                }
                db_records.append(evt)
        except Exception as exc:
            errors.append(f"Failed to read SQLite audit events: {exc}")
        finally:
            if owns_connection:
                db_conn.close()

    if db_ids:
        for idx in range(len(db_ids) - 1):
            curr_id = db_ids[idx]
            next_id = db_ids[idx + 1]
            if next_id < curr_id:
                tampering_detected = True
                tampering_type = "reordering"
                errors.append(f"SQLite ID regression: ID {next_id} follows ID {curr_id} (reordering detected)")
            elif next_id > curr_id + 1:
                tampering_detected = True
                tampering_type = "deletion"
                errors.append(f"SQLite ID gap: ID {next_id} follows ID {curr_id} (deletion detected)")

    eval_records = file_records if file_records else db_records

    prev_time: Optional[datetime] = None
    for idx, event in enumerate(eval_records):
        try:
            _normalize_event(event)
        except Exception as exc:
            tampering_detected = True
            if tampering_type is None:
                tampering_type = "modification"
            errors.append(f"Malformed or tampered record at index {idx}: {exc}")
            continue

        raw_time = event.get("time")
        if isinstance(raw_time, str):
            try:
                curr_time = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                if prev_time is not None and curr_time < prev_time:
                    tampering_detected = True
                    tampering_type = "reordering"
                    errors.append(
                        f"Timestamp regression at index {idx}: {raw_time} precedes earlier timestamp (reordering detected)"
                    )
                prev_time = curr_time
            except Exception:
                tampering_detected = True
                if tampering_type is None:
                    tampering_type = "modification"
                errors.append(f"Invalid timestamp at index {idx}: {raw_time}")

    cross_store_verified = False
    if file_store_expected and db_conn is None and file_records:
        tampering_detected = True
        tampering_type = tampering_type or "deletion"
        errors.append("SQLite audit store is unavailable while JSONL records exist")
    if file_store_expected and target_log_path is not None and not file_store_exists and db_records:
        tampering_detected = True
        tampering_type = tampering_type or "deletion"
        errors.append("JSONL audit store is missing while SQLite records exist")
    elif file_store_expected and target_log_path is not None and file_store_exists and not file_records and db_records:
        tampering_detected = True
        tampering_type = tampering_type or "deletion"
        errors.append("JSONL audit store is unexpectedly empty while SQLite records exist")
    if file_records and db_records:
        if len(file_records) != len(db_records):
            tampering_detected = True
            if tampering_type is None:
                tampering_type = "deletion"
            errors.append(
                f"Cross-store count mismatch: JSONL has {len(file_records)} records, SQLite has {len(db_records)} records (deletion detected)"
            )
        else:
            cross_store_verified = True
            for idx, (f_evt, d_evt) in enumerate(zip(file_records, db_records)):
                for field in AUDIT_FIELDS:
                    if f_evt.get(field) != d_evt.get(field):
                        tampering_detected = True
                        if tampering_type is None:
                            tampering_type = "modification"
                        errors.append(
                            f"Cross-store mismatch at index {idx} on field '{field}': JSONL={f_evt.get(field)!r} vs SQLite={d_evt.get(field)!r} (modification detected)"
                        )
                        cross_store_verified = False
    elif file_store_expected and target_log_path is not None and file_records and not db_records:
        tampering_detected = True
        tampering_type = tampering_type or "deletion"
        errors.append("SQLite audit store is empty or unavailable while JSONL records exist")

    chain_digest = compute_audit_chain_hash(eval_records)
    if expected_chain_digest is not None:
        if not hmac.compare_digest(chain_digest, expected_chain_digest):
            tampering_detected = True
            if tampering_type is None:
                tampering_type = "modification"
            errors.append(
                f"Chain digest mismatch: expected {expected_chain_digest}, computed {chain_digest}"
            )

    return {
        "valid": not bool(errors or tampering_detected),
        "tampering_detected": tampering_detected,
        "tampering_type": tampering_type,
        "record_count": len(eval_records),
        "chain_digest": chain_digest,
        "errors": errors,
        "cross_store_verified": cross_store_verified,
    }

"""Read-only forensic evidence derived from existing audit events."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Mapping, Optional

from server.db import DEFAULT_DB_PATH, PathLike, get_connection


_SENTINEL_MARKER = "sentinel_context="


class ForensicRetrievalError(RuntimeError):
    """Raised when forensic storage cannot be read or validated completely."""


def _value(event: Mapping[str, Any], key: str, default: Any = None) -> Any:
    try:
        return event[key]
    except (KeyError, IndexError):
        return default


def _reason_without_context(reason: str) -> str:
    if _SENTINEL_MARKER not in reason:
        return reason
    return reason.split(" (" + _SENTINEL_MARKER, 1)[0]


def _sentinel_context(reason: str) -> dict[str, Any]:
    if _SENTINEL_MARKER not in reason:
        return {}
    raw = reason.split(_SENTINEL_MARKER, 1)[1].rstrip(")")
    try:
        context = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return context if isinstance(context, dict) else {}


def evidence_from_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Build concise incident evidence without copying protected action data."""

    event_id = _value(event, "id")
    numeric_event_id: Optional[int]
    try:
        numeric_event_id = int(event_id) if event_id is not None else None
    except (TypeError, ValueError):
        numeric_event_id = None
    reason = str(_value(event, "reason", ""))
    context = _sentinel_context(reason)
    refs = [numeric_event_id] if numeric_event_id is not None else []
    request_id = str(_value(event, "request_id", "") or "")
    is_simulation = bool(
        request_id.startswith((
            "REQ-TAMPER",
            "REQ-PATIENT-SUB",
            "REQ-UNAUTHORIZED",
            "REQ-REPLAY",
            "REQ-CHANGED",
            "REQ-PROMPT",
            "REQ-EXPIRED",
            "REQ-REVOKED",
            "REQ-GUARD",
            "REQ-TOOL-REGISTRY",
            "REQ-TEST",
            "REQ-SENTINEL",
        ))
        or "demo" in request_id.lower()
        or "test" in request_id.lower()
        or "tamper" in request_id.lower()
        or "simulat" in request_id.lower()
    )
    return {
        "incident_id": f"INC-{numeric_event_id:06d}" if numeric_event_id is not None else None,
        "event_id": numeric_event_id,
        "time": _value(event, "time"),
        "request_id": _value(event, "request_id"),
        "actor": _value(event, "actor", _value(event, "actor_id")),
        "tool": _value(event, "tool"),
        "failed_check": _value(event, "rule"),
        "expected_fingerprint": context.get("expected_fingerprint"),
        "observed_fingerprint": context.get("observed_fingerprint"),
        "differences": context.get("differences", []),
        "decision": _value(event, "decision"),
        "explanation": _reason_without_context(reason),
        "state_changed": bool(_value(event, "state_changed", False)),
        "audit_event_refs": refs,
        "is_simulation": is_simulation,
        "evidence_type": "simulated_attack" if is_simulation else "runtime_security_event",
    }


def evidence_for_request(
    request_id: str,
    connection: Optional[sqlite3.Connection] = None,
    db_path: Optional[PathLike] = None,
) -> Optional[dict[str, Any]]:
    """Return the newest audit evidence for a request without changing state."""

    owns_connection = connection is None
    if owns_connection:
        path = Path(db_path if db_path is not None else DEFAULT_DB_PATH)
        if not path.exists():
            return None
        current = get_connection(path)
    else:
        current = connection
    try:
        cursor = current.execute(
            "SELECT * FROM audit_events WHERE request_id = ? ORDER BY id DESC LIMIT 1",
            (request_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            event = dict(row)
        else:
            event = dict(zip((column[0] for column in cursor.description), row))
        event["actor"] = event.get("actor_id")
        return evidence_from_event(event)
    finally:
        if owns_connection:
            current.close()


def verify_audit_integrity(
    log_path: Optional[PathLike] = None,
    connection: Optional[sqlite3.Connection] = None,
    db_path: Optional[PathLike] = None,
) -> dict[str, Any]:
    """Check whether modifications, deletions, or reordering occurred in the audit trail."""

    from guard.audit import verify_audit_log_integrity
    from guard import audit

    return verify_audit_log_integrity(
        # When the caller supplies only a connection, still verify the
        # configured JSONL companion store rather than silently checking
        # SQLite alone. Tests can override audit.LOG_PATH for isolation.
        log_path=log_path if log_path is not None else audit.LOG_PATH,
        connection=connection,
        db_path=db_path,
    )


from dataclasses import asdict, dataclass, field


@dataclass
class ForensicEvidenceRecord:
    """Standardized forensic evidence record for technical judge inspection."""

    id: int
    timestamp: str
    event_type: str
    request_id: str
    tool: str
    actor: str
    decision: str
    risk: str
    rule: str
    reason: str
    expected_fingerprint: Optional[str] = None
    observed_fingerprint: Optional[str] = None
    detected_mismatch: list[str] = field(default_factory=list)
    state_changed: bool = False
    is_simulation: bool = False
    raw_payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def get_forensic_events(
    connection: Optional[sqlite3.Connection] = None,
    limit: int = 100,
    decision_filter: Optional[str] = None,
    event_type_filter: Optional[str] = None,
    db_path: Optional[PathLike] = None,
) -> list[ForensicEvidenceRecord]:
    """Retrieve and format forensic evidence records from SQLite audit storage."""
    close_after = False
    target_db = Path(db_path if db_path is not None else DEFAULT_DB_PATH)
    if connection is None:
        if not target_db.exists():
            return []
        connection = get_connection(target_db)
        close_after = True

    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit must be a positive integer")

    records: list[ForensicEvidenceRecord] = []
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'")
        if not cursor.fetchone():
            return []

        query = "SELECT * FROM audit_events ORDER BY id DESC"
        cursor.execute(query)
        rows = cursor.fetchall()

        for row in rows:
            r_dict = dict(row)
            dec = str(r_dict.get("decision", "unknown")).lower()
            if decision_filter and decision_filter.lower() != "all" and dec != decision_filter.lower():
                continue

            tool = str(r_dict.get("tool", "unknown"))
            action_type = str(r_dict.get("action_type", tool))
            if event_type_filter and event_type_filter.lower() != "all" and event_type_filter.lower() not in action_type.lower():
                continue

            req_id = str(r_dict.get("request_id", "REQ-UNKNOWN"))
            is_sim = any(
                prefix in req_id.upper()
                for prefix in ["SIM", "TAMPER", "ATK", "TEST", "REPLAY", "DEMO", "LIVE-"]
            )

            raw_cf = r_dict.get("changed_fields")
            cf_list: list[str] = []
            if isinstance(raw_cf, str) and raw_cf.strip():
                try:
                    loaded = json.loads(raw_cf)
                    if isinstance(loaded, list):
                        cf_list = [str(x) for x in loaded]
                    else:
                        cf_list = [str(loaded)]
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ForensicRetrievalError(
                        f"Audit event {r_dict.get('id', 'unknown')} has malformed changed_fields"
                    ) from exc
            elif isinstance(raw_cf, (list, tuple)):
                cf_list = [str(x) for x in raw_cf]

            expected_fp = None
            observed_fp = None
            reason_text = str(r_dict.get("reason", ""))
            if "fingerprint" in reason_text.lower() or "sha256" in reason_text.lower():
                words = [w.strip(".,;:()") for w in reason_text.split()]
                hex_candidates = [w for w in words if len(w) == 64 and all(c in "0123456789abcdefABCDEF" for c in w)]
                if len(hex_candidates) >= 2:
                    expected_fp = hex_candidates[0]
                    observed_fp = hex_candidates[1]
                elif len(hex_candidates) == 1:
                    observed_fp = hex_candidates[0]

            record = ForensicEvidenceRecord(
                id=int(r_dict.get("id", 0)),
                timestamp=str(r_dict.get("time", "")),
                event_type=action_type,
                request_id=req_id,
                tool=tool,
                actor=str(r_dict.get("actor_id", r_dict.get("actor", "unknown"))),
                decision=dec,
                risk=str(r_dict.get("risk", "medium")),
                rule=str(r_dict.get("rule", "unknown")),
                reason=reason_text,
                expected_fingerprint=expected_fp,
                observed_fingerprint=observed_fp,
                detected_mismatch=cf_list,
                state_changed=bool(r_dict.get("state_changed", False)),
                is_simulation=is_sim,
                raw_payload=r_dict,
            )
            records.append(record)
            if len(records) >= limit:
                break

    except ForensicRetrievalError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError, KeyError) as exc:
        raise ForensicRetrievalError(
            "The forensic store could not be read or validated completely."
        ) from exc
    finally:
        if close_after:
            connection.close()

    return records

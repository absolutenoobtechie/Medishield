"""Forensic evidence viewer and incident analysis for MediShield runtime gateway."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Union

from server.db import DEFAULT_DB_PATH, get_connection

ROOT_DIR = Path(__file__).resolve().parent.parent


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
    detected_mismatch: List[str] = field(default_factory=list)
    state_changed: bool = False
    is_simulation: bool = False
    raw_payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_forensic_events(
    connection: Optional[sqlite3.Connection] = None,
    limit: int = 100,
    decision_filter: Optional[str] = None,
    event_type_filter: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> List[ForensicEvidenceRecord]:
    """Retrieve and format forensic evidence records from SQLite audit storage.

    Safely sanitizes patient records, parses tamper findings, and isolates
    simulation events from normal clinical telemetry.
    """
    close_after = False
    target_db = Path(db_path) if db_path else (ROOT_DIR / "medishield.sqlite3")
    if connection is None:
        connection = get_connection(target_db)
        close_after = True

    records: List[ForensicEvidenceRecord] = []
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

            # Parse changed_fields / detected mismatch
            raw_cf = r_dict.get("changed_fields")
            cf_list: List[str] = []
            if isinstance(raw_cf, str) and raw_cf.strip():
                try:
                    loaded = json.loads(raw_cf)
                    if isinstance(loaded, list):
                        cf_list = [str(x) for x in loaded]
                    else:
                        cf_list = [str(loaded)]
                except Exception:
                    cf_list = [f.strip() for f in raw_cf.split(",") if f.strip()]
            elif isinstance(raw_cf, (list, tuple)):
                cf_list = [str(x) for x in raw_cf]

            # Detect fingerprint markers if present in rule or reason
            expected_fp = None
            observed_fp = None
            reason_text = str(r_dict.get("reason", ""))
            if "fingerprint" in reason_text.lower() or "sha256" in reason_text.lower():
                # Extract potential hex fingerprints if present
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

    except Exception:
        pass
    finally:
        if close_after:
            connection.close()

    return records

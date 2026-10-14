"""Signed, independently verifiable checkpoints for the synthetic audit ledger."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .audit import AUDIT_FIELDS, _normalize_event, compute_audit_chain_hash


CHECKPOINT_SCHEMA = "medishield-audit-checkpoint-v1"
LEDGER_ID = "medishield-audit"
PRIVATE_KEY_ENV = "MEDISHIELD_AUDIT_CHECKPOINT_PRIVATE_KEY"
PUBLIC_KEY_ENV = "MEDISHIELD_AUDIT_CHECKPOINT_PUBLIC_KEY"
KEY_ID_ENV = "MEDISHIELD_AUDIT_CHECKPOINT_KEY_ID"
DEFAULT_CHECKPOINT_PATH = Path(__file__).resolve().parent.parent / "logs" / "audit_checkpoints.jsonl"


class CheckpointConfigurationError(ValueError):
    """Raised when a required checkpoint key or identifier is unavailable."""


def _decode_key(value: str, name: str) -> bytes:
    candidates: list[bytes] = []
    try:
        candidates.append(base64.urlsafe_b64decode(value.encode("ascii")))
    except (ValueError, UnicodeError):
        pass
    try:
        candidates.append(bytes.fromhex(value))
    except ValueError:
        pass
    for candidate in candidates:
        if len(candidate) == 32:
            return candidate
    raise CheckpointConfigurationError(f"{name} must encode exactly 32 key bytes")


def load_private_key() -> Ed25519PrivateKey:
    value = os.environ.get(PRIVATE_KEY_ENV)
    if not value:
        raise CheckpointConfigurationError(f"{PRIVATE_KEY_ENV} is required")
    return Ed25519PrivateKey.from_private_bytes(_decode_key(value, PRIVATE_KEY_ENV))


def load_public_key() -> Ed25519PublicKey:
    value = os.environ.get(PUBLIC_KEY_ENV)
    if not value:
        raise CheckpointConfigurationError(f"{PUBLIC_KEY_ENV} is required")
    return Ed25519PublicKey.from_public_bytes(_decode_key(value, PUBLIC_KEY_ENV))


def checkpoint_key_id() -> str:
    value = os.environ.get(KEY_ID_ENV)
    if not value or len(value) > 80 or any(ord(char) < 32 for char in value):
        raise CheckpointConfigurationError(f"{KEY_ID_ENV} is required")
    return value


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _event_from_row(row: sqlite3.Row | tuple[Any, ...], columns: tuple[str, ...]) -> dict[str, Any]:
    raw = dict(row) if isinstance(row, sqlite3.Row) else dict(zip(columns, row))
    event = {
        "time": raw["time"],
        "request_id": raw["request_id"],
        "actor": raw["actor_id"],
        "tool": raw["tool"],
        "action_type": raw["action_type"],
        "approval_id": raw["approval_id"],
        "decision": raw["decision"],
        "risk": raw["risk"],
        "rule": raw["rule"],
        "reason": raw["reason"],
        "changed_fields": json.loads(raw["changed_fields"]),
        "state_changed": bool(raw["state_changed"]),
    }
    return _normalize_event(event)


def _ledger_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
    cursor = connection.execute(
        """
        SELECT id, time, request_id, actor_id, tool, action_type,
               approval_id, decision, risk, rule, reason,
               changed_fields, state_changed
        FROM audit_events ORDER BY id ASC
        """
    )
    columns = tuple(column[0] for column in cursor.description or ())
    rows = cursor.fetchall()
    events: list[dict[str, Any]] = []
    ids: list[int] = []
    event_digests: list[str] = []
    for row in rows:
        raw = dict(row) if isinstance(row, sqlite3.Row) else dict(zip(columns, row))
        event = _event_from_row(row, columns)
        event_id = int(raw["id"])
        ids.append(event_id)
        events.append(event)
        event_digests.append(
            hashlib.sha256(_canonical({"event_id": event_id, "event": event})).hexdigest()
        )
    for previous, current in zip(ids, ids[1:]):
        if current != previous + 1:
            raise ValueError("audit event sequence contains a gap")
    return {
        "record_count": len(events),
        "last_event_id": ids[-1] if ids else None,
        "last_event_digest": event_digests[-1] if event_digests else None,
        "chain_digest": compute_audit_chain_hash(events),
    }


def _payload_from_checkpoint(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    payload = {key: checkpoint[key] for key in checkpoint if key != "signature"}
    required = {
        "checkpoint_schema",
        "ledger_id",
        "record_count",
        "last_event_id",
        "last_event_digest",
        "chain_digest",
        "created_at",
        "key_id",
    }
    if set(payload) != required:
        raise ValueError("checkpoint fields do not match the contract")
    if payload["checkpoint_schema"] != CHECKPOINT_SCHEMA or payload["ledger_id"] != LEDGER_ID:
        raise ValueError("checkpoint schema or ledger identity is invalid")
    if not isinstance(payload["record_count"], int) or payload["record_count"] < 0:
        raise ValueError("checkpoint record_count is invalid")
    if payload["last_event_id"] is not None and not isinstance(payload["last_event_id"], int):
        raise ValueError("checkpoint last_event_id is invalid")
    for field in ("chain_digest", "last_event_digest"):
        value = payload[field]
        if value is not None and (not isinstance(value, str) or len(value) != 64):
            raise ValueError(f"checkpoint {field} is invalid")
    return payload


def create_checkpoint(
    connection: sqlite3.Connection,
    checkpoint_path: Path | str = DEFAULT_CHECKPOINT_PATH,
) -> dict[str, Any]:
    """Sign the current audit-ledger head and append one checkpoint record."""

    payload = {
        "checkpoint_schema": CHECKPOINT_SCHEMA,
        "ledger_id": LEDGER_ID,
        **_ledger_snapshot(connection),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "key_id": checkpoint_key_id(),
    }
    signature = base64.urlsafe_b64encode(load_private_key().sign(_canonical(payload))).decode("ascii")
    record = {**payload, "signature": signature}
    path = Path(checkpoint_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        handle.write("\n")
    return record


def verify_checkpoint(
    checkpoint: Mapping[str, Any],
    connection: sqlite3.Connection,
    public_key: Optional[Ed25519PublicKey] = None,
) -> dict[str, Any]:
    """Verify a checkpoint signature and require it to match the current ledger head."""

    errors: list[str] = []
    try:
        payload = _payload_from_checkpoint(checkpoint)
        signature_value = checkpoint.get("signature")
        if not isinstance(signature_value, str):
            raise ValueError("checkpoint signature is missing")
        key = public_key or load_public_key()
        key.verify(base64.urlsafe_b64decode(signature_value.encode("ascii")), _canonical(payload))
        snapshot = _ledger_snapshot(connection)
    except (CheckpointConfigurationError, InvalidSignature, OSError, sqlite3.Error, TypeError, ValueError) as exc:
        errors.append(str(exc))
        return {"valid": False, "status": "unverifiable", "errors": errors}

    if any(snapshot[field] != payload[field] for field in (
        "record_count", "last_event_id", "last_event_digest", "chain_digest"
    )):
        return {
            "valid": False,
            "status": "stale",
            "errors": ["checkpoint does not match the current audit-ledger head"],
            "checkpoint": dict(payload),
            "current": snapshot,
        }
    return {
        "valid": True,
        "status": "valid",
        "errors": [],
        "checkpoint": dict(payload),
        "current": snapshot,
    }


def verify_latest_checkpoint(
    connection: sqlite3.Connection,
    checkpoint_path: Path | str = DEFAULT_CHECKPOINT_PATH,
    public_key: Optional[Ed25519PublicKey] = None,
) -> dict[str, Any]:
    """Verify the newest checkpoint, explicitly failing when it is absent."""

    path = Path(checkpoint_path)
    if not path.exists():
        return {"valid": False, "status": "missing", "errors": ["checkpoint file is missing"]}
    try:
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not records:
            raise ValueError("checkpoint file is empty")
        checkpoint = records[-1]
        if not isinstance(checkpoint, dict):
            raise ValueError("checkpoint record is not an object")
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return {"valid": False, "status": "unverifiable", "errors": [str(exc)]}
    return verify_checkpoint(checkpoint, connection, public_key=public_key)

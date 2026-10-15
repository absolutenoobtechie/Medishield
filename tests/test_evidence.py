"""Isolated tests for signed audit checkpoints and privacy receipts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guard import audit
from guard.checkpoints import create_checkpoint, verify_latest_checkpoint
from guard.forensics import ForensicRetrievalError, get_forensic_events
from privacy.vault import (
    StorageConfigurationError,
    delete_document,
    reconcile_deletions,
    verify_document_receipt,
    upload_document,
)
from privacy.auth import authenticate_local
from server.db import initialize_db


def _event(request_id: str) -> dict[str, object]:
    return {
        "time": "2026-10-15T08:00:00Z",
        "request_id": request_id,
        "actor": "system",
        "tool": "test",
        "action_type": "test",
        "approval_id": None,
        "decision": "blocked",
        "risk": "low",
        "rule": "synthetic test",
        "reason": "Synthetic checkpoint test.",
        "changed_fields": [],
        "state_changed": False,
    }


def test_signed_checkpoint_matches_then_detects_new_ledger_state(tmp_path, monkeypatch):
    connection = initialize_db(tmp_path / "checkpoint.sqlite3")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "logs" / "events.jsonl")
    audit.record_audit_event(_event("REQ-CP-001"), connection=connection)
    connection.commit()
    checkpoint_path = tmp_path / "checkpoints.jsonl"

    create_checkpoint(connection, checkpoint_path)
    assert verify_latest_checkpoint(connection, checkpoint_path)["status"] == "valid"

    audit.record_audit_event(_event("REQ-CP-002"), connection=connection)
    connection.commit()
    result = verify_latest_checkpoint(connection, checkpoint_path)
    assert result["valid"] is False
    assert result["status"] == "stale"
    connection.close()


def test_missing_checkpoint_fails_closed(tmp_path):
    connection = initialize_db(tmp_path / "checkpoint.sqlite3")
    result = verify_latest_checkpoint(connection, tmp_path / "missing.jsonl")
    assert result == {
        "valid": False,
        "status": "missing",
        "errors": ["checkpoint file is missing"],
    }
    connection.close()


def test_privacy_receipt_detects_artifact_tampering(tmp_path, monkeypatch):
    connection = initialize_db(tmp_path / "privacy.sqlite3")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "logs" / "events.jsonl")
    root = tmp_path / "vault"
    user = authenticate_local(connection, "clinician_1", "ORG-DEMO")
    uploaded = upload_document(
        connection,
        user,
        "receipt.txt",
        b"Synthetic Patient Alpha\nMRN: DEMO-001",
        storage_root=root,
    )

    receipt = verify_document_receipt(connection, user, uploaded["document_id"], storage_root=root)
    assert receipt["valid"] is True
    assert receipt["signature_valid"] is True
    assert receipt["artifact_digests_match"] is True

    row = connection.execute(
        "SELECT original_path FROM documents WHERE document_id = ?",
        (uploaded["document_id"],),
    ).fetchone()
    path = root / row[0]
    path.write_bytes(path.read_bytes() + b"tamper")

    invalid = verify_document_receipt(
        connection,
        user,
        uploaded["document_id"],
        storage_root=root,
    )
    assert invalid["valid"] is False
    assert invalid["signature_valid"] is True
    assert invalid["artifact_digests_match"] is False
    connection.close()


def test_missing_receipt_key_fails_closed_before_document_commit(tmp_path, monkeypatch):
    connection = initialize_db(tmp_path / "privacy.sqlite3")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "logs" / "events.jsonl")
    monkeypatch.delenv("MEDISHIELD_RECEIPT_SIGNING_PRIVATE_KEY", raising=False)
    root = tmp_path / "vault"
    user = authenticate_local(connection, "clinician_1", "ORG-DEMO")

    with pytest.raises(StorageConfigurationError):
        upload_document(connection, user, "receipt.txt", b"synthetic", storage_root=root)

    assert connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 0
    assert list(root.rglob("*.msd")) == []
    connection.close()


def test_deletion_retains_tombstone_and_reconciliation_is_idempotent(tmp_path, monkeypatch):
    connection = initialize_db(tmp_path / "privacy.sqlite3")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "logs" / "events.jsonl")
    root = tmp_path / "vault"
    user = authenticate_local(connection, "clinician_1", "ORG-DEMO")
    admin = authenticate_local(connection, "org_admin_1", "ORG-DEMO")
    uploaded = upload_document(
        connection,
        user,
        "delete.txt",
        b"synthetic deletion fixture",
        storage_root=root,
    )

    delete_document(connection, admin, uploaded["document_id"], storage_root=root)
    row = connection.execute(
        "SELECT deletion_status, original_path FROM documents WHERE document_id = ?",
        (uploaded["document_id"],),
    ).fetchone()
    assert row[0] == "deleted"
    assert (root / row[1]).exists() is False
    assert reconcile_deletions(connection, admin, storage_root=root) == []
    connection.close()


def test_deletion_storage_failure_is_recoverable(tmp_path, monkeypatch):
    connection = initialize_db(tmp_path / "privacy.sqlite3")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "logs" / "events.jsonl")
    root = tmp_path / "vault"
    user = authenticate_local(connection, "clinician_1", "ORG-DEMO")
    admin = authenticate_local(connection, "org_admin_1", "ORG-DEMO")
    uploaded = upload_document(
        connection,
        user,
        "recover.txt",
        b"synthetic deletion recovery fixture",
        storage_root=root,
    )

    original_unlink = Path.unlink
    failed_once = False

    def fail_first_unlink(path, missing_ok=False):
        nonlocal failed_once
        if not failed_once:
            failed_once = True
            raise OSError("synthetic storage failure")
        return original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fail_first_unlink)
    with pytest.raises(StorageConfigurationError):
        delete_document(connection, admin, uploaded["document_id"], storage_root=root)
    monkeypatch.setattr(Path, "unlink", original_unlink)

    status = connection.execute(
        "SELECT deletion_status FROM documents WHERE document_id = ?",
        (uploaded["document_id"],),
    ).fetchone()[0]
    assert status == "failed"
    assert reconcile_deletions(connection, admin, storage_root=root) == [uploaded["document_id"]]
    connection.close()


def test_forensic_reader_raises_on_malformed_event_storage(tmp_path, monkeypatch):
    connection = initialize_db(tmp_path / "forensic.sqlite3")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "logs" / "events.jsonl")
    audit.record_audit_event(_event("REQ-FORENSIC-001"), connection=connection)
    connection.commit()
    connection.execute(
        "UPDATE audit_events SET changed_fields = ? WHERE request_id = ?",
        ("not-json", "REQ-FORENSIC-001"),
    )
    connection.commit()

    with pytest.raises(ForensicRetrievalError):
        get_forensic_events(connection=connection)
    connection.close()

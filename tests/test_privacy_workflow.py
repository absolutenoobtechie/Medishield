"""Isolated synthetic end-to-end tests for the document privacy MVP."""

from __future__ import annotations

import json

import pytest

from privacy.auth import AuthorizationError, authenticate_local
from privacy.deid import deidentify_text
from privacy.vault import (
    DocumentIntegrityError,
    DocumentValidationError,
    StorageConfigurationError,
    list_documents,
    retrieve_document,
    review_document,
    upload_document,
    verify_document_integrity,
)
from server.db import initialize_db
from guard import audit
from demo.attacks import document_vault_workflow


@pytest.fixture
def vault_context(tmp_path, monkeypatch):
    monkeypatch.setenv("MEDISHIELD_DOCUMENT_KEY", "11" * 32)
    monkeypatch.setenv("MEDISHIELD_PSEUDONYM_SECRET", "22" * 32)
    db = initialize_db(tmp_path / "vault.sqlite3")
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "logs" / "events.jsonl")
    yield db, tmp_path / "vault"
    db.close()


def _user(connection, actor_id: str, org_id: str = "ORG-DEMO"):
    return authenticate_local(connection, actor_id, org_id)


def _note() -> bytes:
    return (
        b"Patient Name: John Doe\n"
        b"DOB: 12/05/1980\n"
        b"MRN: MRN-123\n"
        b"Phone: 555-010-1234\n"
        b"Email: john@example.com\n"
        b"Assessment: synthetic diabetes follow-up; continue metformin."
    )


def test_upload_review_and_tenant_authorized_derivative_retrieval(vault_context):
    connection, root = vault_context
    upload = upload_document(connection, _user(connection, "clinician_1"), "synthetic-note.txt", _note(), storage_root=root)

    assert upload["status"] == "pending_review"
    assert upload["review_required"] is True
    assert {"person", "date", "mrn", "phone", "email"} <= set(upload["report"]["counts"])
    assert "John Doe" not in json.dumps(upload["report"])

    files = list(root.rglob("*.msd"))
    assert len(files) == 2
    assert all(b"John Doe" not in item.read_bytes() for item in files)

    with pytest.raises(AuthorizationError):
        retrieve_document(connection, _user(connection, "nurse_1"), upload["document_id"], storage_root=root)

    reviewed = review_document(
        connection,
        _user(connection, "privacy_1"),
        upload["document_id"],
        "approve",
        storage_root=root,
    )
    assert reviewed["status"] == "approved"

    derivative = retrieve_document(
        connection,
        _user(connection, "researcher_1"),
        upload["document_id"],
        storage_root=root,
    )
    assert b"John Doe" not in derivative
    assert b"john@example.com" not in derivative
    assert b"[PERSON_1]" in derivative
    assert b"metformin" in derivative

    original = retrieve_document(
        connection,
        _user(connection, "clinician_1"),
        upload["document_id"],
        variant="original",
        storage_root=root,
    )
    assert original == _note()


def test_tenant_boundary_and_metadata_do_not_return_content(vault_context):
    connection, root = vault_context
    connection.execute(
        "INSERT OR IGNORE INTO memberships(org_id, actor_id, role, active) VALUES (?, ?, ?, 1)",
        ("ORG-SECOND", "researcher_1", "researcher"),
    )
    connection.commit()
    upload = upload_document(connection, _user(connection, "clinician_1"), "note.txt", _note(), storage_root=root)

    metadata = list_documents(connection, _user(connection, "researcher_1"))
    assert metadata[0]["document_id"] == upload["document_id"]
    assert "text" not in metadata[0]
    assert list_documents(connection, _user(connection, "researcher_1", "ORG-SECOND")) == []


def test_ciphertext_tampering_is_detected_without_returning_plaintext(vault_context):
    connection, root = vault_context
    upload = upload_document(connection, _user(connection, "clinician_1"), "note.txt", _note(), storage_root=root)
    review_document(
        connection,
        _user(connection, "privacy_1"),
        upload["document_id"],
        "approve",
        storage_root=root,
    )
    row = connection.execute(
        "SELECT derivative_path FROM documents WHERE document_id = ?",
        (upload["document_id"],),
    ).fetchone()
    path = root / row[0]
    tampered = bytearray(path.read_bytes())
    tampered[-1] ^= 0x01
    path.write_bytes(tampered)

    with pytest.raises(DocumentIntegrityError):
        retrieve_document(
            connection,
            _user(connection, "researcher_1"),
            upload["document_id"],
            storage_root=root,
        )
    event = connection.execute(
        "SELECT rule, decision, state_changed FROM audit_events WHERE request_id = ? ORDER BY id DESC LIMIT 1",
        (upload["document_id"],),
    ).fetchone()
    assert event["decision"] == "blocked"
    assert event["state_changed"] == 0
    assert "integrity" in event["rule"]
    assert verify_document_integrity(connection, _user(connection, "auditor_1"), upload["document_id"], storage_root=root)["valid"] is False


def test_missing_document_key_fails_closed(vault_context, monkeypatch):
    connection, root = vault_context
    monkeypatch.delenv("MEDISHIELD_DOCUMENT_KEY", raising=False)
    with pytest.raises(StorageConfigurationError):
        upload_document(connection, _user(connection, "clinician_1"), "note.txt", b"synthetic", storage_root=root)
    assert connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 0


def test_pseudonymization_is_stable_and_report_has_no_raw_identifier(monkeypatch):
    monkeypatch.setenv("MEDISHIELD_PSEUDONYM_SECRET", "22" * 32)
    first = deidentify_text("Patient Name: John Doe; MRN: MRN-123", mode="pseudonymization", org_id="ORG-DEMO")
    second = deidentify_text("Patient Name: John Doe; MRN: MRN-123", mode="pseudonymization", org_id="ORG-DEMO")
    other_org = deidentify_text("Patient Name: John Doe; MRN: MRN-123", mode="pseudonymization", org_id="ORG-SECOND")
    assert first.text == second.text
    assert first.text != other_org.text
    assert "John Doe" not in json.dumps(first.report())
    assert "MRN-123" not in json.dumps(first.report())


def test_detection_only_never_creates_a_shareable_plaintext_derivative(vault_context):
    connection, root = vault_context
    upload = upload_document(
        connection,
        _user(connection, "clinician_1"),
        "review-only.txt",
        _note(),
        mode="detection",
        storage_root=root,
    )
    assert upload["derivative_sha256"] is None
    assert len(list(root.rglob("*.msd"))) == 1
    review_document(
        connection,
        _user(connection, "privacy_1"),
        upload["document_id"],
        "approve",
        storage_root=root,
    )
    with pytest.raises(DocumentValidationError):
        retrieve_document(
            connection,
            _user(connection, "researcher_1"),
            upload["document_id"],
            storage_root=root,
        )


def test_upload_rejects_path_traversal_and_mismatched_signature(vault_context):
    connection, root = vault_context
    with pytest.raises(DocumentValidationError):
        upload_document(connection, _user(connection, "clinician_1"), "..\\secret.txt", b"synthetic", storage_root=root)
    with pytest.raises(DocumentValidationError):
        upload_document(connection, _user(connection, "clinician_1"), "fake.pdf", b"not a pdf", storage_root=root)


def test_document_demo_uses_real_upload_review_retrieval_and_tamper_detection():
    result = document_vault_workflow()
    assert result["uploaded"]["status"] == "pending_review"
    assert result["approved_status"] == "approved"
    assert result["derivative_contains_raw_name"] is False
    assert result["derivative_contains_clinical_text"] is True
    assert result["tamper_detected"] is True

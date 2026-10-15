"""Tenant-scoped encrypted document vault for the synthetic MVP."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import uuid
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from guard import audit

from .auth import AuthorizationError, WorkspaceUser, require_permission
from .crypto import (
    DecryptionError,
    KeyConfigurationError,
    decrypt_bytes,
    encrypt_bytes,
    load_document_key,
    sha256_hex,
)
from .deid import deidentify_text
from .receipts import (
    PIPELINE_VERSION,
    ReceiptConfigurationError,
    key_id as receipt_key_id,
    sign_receipt,
    verify_receipt_signature,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STORAGE_ROOT = REPOSITORY_ROOT / ".medishield_vault"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".png", ".jpg", ".jpeg"}
_ORG_ID = re.compile(r"^[A-Z0-9][A-Z0-9_-]{2,63}$")


class DocumentValidationError(ValueError):
    """Raised when a document is not a safe supported upload."""


class StorageConfigurationError(RuntimeError):
    """Raised when protected storage cannot be configured safely."""


class DocumentIntegrityError(RuntimeError):
    """Raised when ciphertext or stored content hashes do not verify."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_filename(filename: str) -> str:
    if not isinstance(filename, str) or not filename.strip():
        raise DocumentValidationError("a filename is required")
    candidate = Path(filename).name
    if candidate in {"", ".", ".."} or "/" in filename or "\\" in filename:
        raise DocumentValidationError("path components are not allowed in filenames")
    if any(ord(char) < 32 for char in candidate) or len(candidate) > 120:
        raise DocumentValidationError("filename contains unsafe characters")
    return candidate


def _validate_upload(filename: str, content: bytes) -> tuple[str, str, str]:
    safe_name = _safe_filename(filename)
    if not isinstance(content, (bytes, bytearray)):
        raise DocumentValidationError("upload content must be bytes")
    payload = bytes(content)
    if not payload:
        raise DocumentValidationError("empty uploads are not accepted")
    if len(payload) > MAX_UPLOAD_BYTES:
        raise DocumentValidationError("upload exceeds the 10 MiB demo limit")
    extension = Path(safe_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise DocumentValidationError("only TXT, PDF, PNG, and JPEG files are supported")

    if extension == ".txt":
        if b"\x00" in payload:
            raise DocumentValidationError("the text file contains binary data")
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError:
            raise DocumentValidationError("text uploads must be valid UTF-8") from None
        media_type = "text/plain"
    elif extension == ".pdf":
        if not payload.startswith(b"%PDF-"):
            raise DocumentValidationError("file extension does not match a PDF signature")
        media_type = "application/pdf"
    elif extension == ".png":
        if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
            raise DocumentValidationError("file extension does not match a PNG signature")
        media_type = "image/png"
    else:
        if not payload.startswith(b"\xff\xd8\xff"):
            raise DocumentValidationError("file extension does not match a JPEG signature")
        media_type = "image/jpeg"
    return safe_name, extension, media_type


def _extract_text(content: bytes, extension: str) -> tuple[str | None, str, list[str]]:
    if extension == ".txt":
        return content.decode("utf-8"), "extracted", []
    if extension == ".pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(BytesIO(content), strict=True)
            if reader.is_encrypted:
                raise DocumentValidationError("encrypted PDFs require manual review")
            text = "\n".join((page.extract_text() or "") for page in reader.pages)
            if not text.strip():
                return None, "no_text", ["PDF contained no extractable text; manual review is required."]
            return text, "extracted", []
        except DocumentValidationError:
            raise
        except Exception as exc:
            raise DocumentValidationError("PDF extraction failed; manual review is required") from exc
    return None, "not_available", ["Local OCR is not configured; image de-identification requires manual review."]


def _aad(document_id: str, org_id: str, variant: str) -> bytes:
    return f"medishield-document:v1:{document_id}:{org_id}:{variant}".encode("utf-8")


def _path_for(root: Path, org_id: str, document_id: str, variant: str) -> Path:
    if not _ORG_ID.fullmatch(org_id):
        raise StorageConfigurationError("organization identifier is invalid")
    return root / org_id / f"{document_id}.{variant}.msd"


def _write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _audit_document(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    actor: str,
    action_type: str,
    decision: str,
    risk: str,
    rule: str,
    reason: str,
    state_changed: bool,
) -> int:
    return audit.record_audit_event(
        {
            "time": _utc_now(),
            "request_id": request_id,
            "actor": actor,
            "tool": "document_vault",
            "action_type": action_type,
            "approval_id": None,
            "decision": decision,
            "risk": risk,
            "rule": rule,
            "reason": reason,
            "changed_fields": [],
            "state_changed": state_changed,
        },
        connection=connection,
    )


def _audit_blocked(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    actor: str,
    action_type: str,
    rule: str,
    reason: str,
) -> None:
    """Write one sanitized denial without committing a caller-owned transaction."""

    savepoint = "vault_denial_audit"
    caller_transaction = connection.in_transaction
    try:
        if caller_transaction:
            connection.execute(f"SAVEPOINT {savepoint}")
        event_id = _audit_document(
            connection,
            request_id=request_id,
            actor=actor,
            action_type=action_type,
            decision="blocked",
            risk="high",
            rule=rule,
            reason=reason,
            state_changed=False,
        )
        if caller_transaction:
            connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        else:
            connection.commit()
    except Exception:
        try:
            if caller_transaction:
                connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            else:
                connection.rollback()
        except sqlite3.Error:
            pass
        raise


def _encrypted_file_digest(path: Path) -> str:
    return sha256_hex(path.read_bytes())


def _build_receipt(
    row: sqlite3.Row,
    *,
    root: Path,
    audit_event_id: int | None,
    checkpoint_ref: str | None = None,
) -> tuple[str, str, str]:
    original_path = (root / row["original_path"]).resolve()
    derivative_path = (
        (root / row["derivative_path"]).resolve() if row["derivative_path"] else None
    )
    if root not in original_path.parents or (
        derivative_path is not None and root not in derivative_path.parents
    ):
        raise StorageConfigurationError("stored document path escaped the private vault")
    report = json.loads(row["findings_json"])
    payload = {
        "receipt_schema": "medishield-privacy-receipt-v1",
        "document_id": row["document_id"],
        "org_id": row["org_id"],
        "original_encrypted_sha256": _encrypted_file_digest(original_path),
        "derivative_encrypted_sha256": (
            _encrypted_file_digest(derivative_path) if derivative_path is not None else None
        ),
        "mode": row["mode"],
        "pipeline_version": PIPELINE_VERSION,
        "detection_summary": report.get("counts", {}),
        "status": row["status"],
        "review_required": bool(row["review_required"]),
        "scanner_status": row["scanner_status"],
        "extraction_status": row["extraction_status"],
        "audit_event_id": audit_event_id,
        "checkpoint_ref": checkpoint_ref,
        "created_at": _utc_now(),
    }
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        sign_receipt(payload),
        receipt_key_id(),
    )


def _persist_receipt(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    root: Path,
    audit_event_id: int | None,
    checkpoint_ref: str | None = None,
) -> None:
    try:
        receipt_json, signature, signing_key_id = _build_receipt(
            row,
            root=root,
            audit_event_id=audit_event_id,
            checkpoint_ref=checkpoint_ref,
        )
    except ReceiptConfigurationError as exc:
        raise StorageConfigurationError("privacy receipt signing is unavailable") from exc
    connection.execute(
        """
        UPDATE documents
        SET receipt_json = ?, receipt_signature = ?, receipt_key_id = ?, updated_at = ?
        WHERE document_id = ? AND org_id = ?
        """,
        (
            receipt_json,
            signature,
            signing_key_id,
            _utc_now(),
            row["document_id"],
            row["org_id"],
        ),
    )


def _require_document(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    document_id: str,
    permission: str,
) -> sqlite3.Row:
    try:
        current = require_permission(connection, user, permission)
    except AuthorizationError:
        _audit_blocked(
            connection,
            request_id=f"document:{document_id}",
            actor=user.actor_id,
            action_type=f"document_{permission}",
            rule="document authorization denied",
            reason="The authenticated role is not permitted to perform this document operation.",
        )
        raise
    row = connection.execute(
        "SELECT * FROM documents WHERE document_id = ? AND org_id = ?",
        (document_id, current.org_id),
    ).fetchone()
    if row is None:
        _audit_blocked(
            connection,
            request_id=f"document:{document_id}",
            actor=current.actor_id,
            action_type=f"document_{permission}",
            rule="document organization scope denied",
            reason="The document is not available in the authenticated organization scope.",
        )
        raise LookupError("document was not found in the authenticated organization")
    if row["deletion_status"] != "active":
        _audit_blocked(
            connection,
            request_id=f"document:{document_id}",
            actor=current.actor_id,
            action_type=f"document_{permission}",
            rule="document deletion lifecycle",
            reason="The document is unavailable while its deletion lifecycle is incomplete.",
        )
        raise AuthorizationError("document is unavailable")
    return row


def upload_document(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    filename: str,
    content: bytes,
    *,
    mode: str = "redaction",
    storage_root: Path | str = DEFAULT_STORAGE_ROOT,
) -> dict[str, Any]:
    """Validate, de-identify, encrypt, and persist one tenant-owned document."""

    current = require_permission(connection, user, "upload")
    if mode not in {"redaction", "pseudonymization", "detection"}:
        raise DocumentValidationError("mode must be redaction, pseudonymization, or detection")
    safe_name, extension, media_type = _validate_upload(filename, content)
    try:
        key = load_document_key()
    except KeyConfigurationError as exc:
        raise StorageConfigurationError("document encryption key is unavailable") from exc
    document_id = f"DOC-{uuid.uuid4().hex}"
    root = Path(storage_root).resolve()
    original_path = _path_for(root, current.org_id, document_id, "original")
    derivative_path: Path | None = None
    original_payload = bytes(content)
    text, extraction_status, warnings = _extract_text(original_payload, extension)
    report: dict[str, Any] = {
        "mode": mode,
        "findings": [],
        "counts": {},
        "review_required": True,
        "warnings": list(warnings),
    }
    derivative_payload: bytes | None = None
    if text is not None:
        try:
            result = deidentify_text(text, mode=mode, org_id=current.org_id)
        except KeyConfigurationError as exc:
            raise StorageConfigurationError("pseudonymization secret is unavailable") from exc
        report = result.report()
        # Detection-only is intentionally not a shareable derivative: storing
        # the unchanged plaintext would let a later reviewer approval expose
        # identifiers to derivative-only roles.
        if mode != "detection":
            derivative_payload = result.text.encode("utf-8")
        else:
            report["warnings"].append("Detection-only mode does not create a retrievable derivative.")
    else:
        report["warnings"].append("No de-identified derivative was generated.")

    now = _utc_now()
    encrypted_original = encrypt_bytes(original_payload, aad=_aad(document_id, current.org_id, "original"), key=key)
    encrypted_derivative: bytes | None = None
    if derivative_payload is not None:
        derivative_path = _path_for(root, current.org_id, document_id, "derivative")
        encrypted_derivative = encrypt_bytes(
            derivative_payload,
            aad=_aad(document_id, current.org_id, "derivative"),
            key=key,
        )

    # No scanner is silently treated as a pass.  The privacy-review state is
    # mandatory until a reviewer explicitly approves the record.
    scanner_status = "not_configured"
    status = "pending_review"
    relative_original = str(original_path.relative_to(root))
    relative_derivative = str(derivative_path.relative_to(root)) if derivative_path else None
    written: list[Path] = []
    try:
        _write_private(original_path, encrypted_original)
        written.append(original_path)
        if derivative_path is not None and encrypted_derivative is not None:
            _write_private(derivative_path, encrypted_derivative)
            written.append(derivative_path)
        connection.execute(
            """
            INSERT INTO documents(
                document_id, org_id, owner_actor_id, original_filename,
                media_type, extension, size_bytes, original_path,
                derivative_path, original_sha256, derivative_sha256, mode,
                status, review_required, findings_json, scanner_status,
                extraction_status, processing_error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                document_id,
                current.org_id,
                current.actor_id,
                safe_name,
                media_type,
                extension,
                len(original_payload),
                relative_original,
                relative_derivative,
                sha256_hex(original_payload),
                sha256_hex(derivative_payload) if derivative_payload is not None else None,
                mode,
                status,
                1,
                json.dumps(report, ensure_ascii=False, separators=(",", ":")),
                scanner_status,
                extraction_status,
                None,
                now,
                now,
            ),
        )
        event_id = _audit_document(
            connection,
            request_id=document_id,
            actor=current.actor_id,
            action_type="document_uploaded",
            decision="allowed",
            risk="medium",
            rule="tenant upload and encrypted storage",
            reason="Synthetic document stored encrypted and queued for privacy review.",
            state_changed=True,
        )
        stored_row = connection.execute(
            "SELECT * FROM documents WHERE document_id = ? AND org_id = ?",
            (document_id, current.org_id),
        ).fetchone()
        if stored_row is None:
            raise StorageConfigurationError("stored document metadata could not be reloaded")
        _persist_receipt(
            connection,
            stored_row,
            root=root,
            audit_event_id=event_id,
        )
        connection.commit()
    except Exception:
        connection.rollback()
        for path in written:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return get_document_metadata(connection, current, document_id)


def get_document_metadata(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    document_id: str,
) -> dict[str, Any]:
    """Return non-content metadata and the sanitized de-identification report."""

    row = _require_document(connection, user, document_id, "metadata")
    report = json.loads(row["findings_json"])
    return {
        "document_id": row["document_id"],
        "org_id": row["org_id"],
        "media_type": row["media_type"],
        "extension": row["extension"],
        "size_bytes": row["size_bytes"],
        "status": row["status"],
        "review_required": bool(row["review_required"]),
        "scanner_status": row["scanner_status"],
        "extraction_status": row["extraction_status"],
        "report": report,
        "original_sha256": row["original_sha256"],
        "derivative_sha256": row["derivative_sha256"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "deletion_status": row["deletion_status"],
        "receipt_available": bool(row["receipt_json"] and row["receipt_signature"]),
        "receipt_key_id": row["receipt_key_id"],
    }


def list_documents(connection: sqlite3.Connection, user: WorkspaceUser) -> list[dict[str, Any]]:
    """List only metadata for the authenticated tenant."""

    current = require_permission(connection, user, "metadata")
    rows = connection.execute(
        "SELECT document_id FROM documents WHERE org_id = ? AND deletion_status = 'active' ORDER BY created_at DESC, document_id",
        (current.org_id,),
    ).fetchall()
    return [get_document_metadata(connection, current, row[0]) for row in rows]


def review_document(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    document_id: str,
    decision: str,
    *,
    storage_root: Path | str = DEFAULT_STORAGE_ROOT,
) -> dict[str, Any]:
    """Approve or reject a queued document using a privacy-officer role."""

    current = _require_document(connection, user, document_id, "review")
    if decision not in {"approve", "reject"}:
        raise ValueError("decision must be approve or reject")
    status = "approved" if decision == "approve" else "rejected"
    try:
        connection.execute(
            "UPDATE documents SET status = ?, review_required = 0, updated_at = ? WHERE document_id = ?",
            (status, _utc_now(), document_id),
        )
        event_id = _audit_document(
            connection,
            request_id=document_id,
            actor=current["owner_actor_id"] if current["owner_actor_id"] == user.actor_id else user.actor_id,
            action_type="document_reviewed",
            decision="allowed",
            risk="low",
            rule="privacy review",
            reason=f"Privacy reviewer marked the synthetic document {status}.",
            state_changed=True,
        )
        refreshed = connection.execute(
            "SELECT * FROM documents WHERE document_id = ? AND org_id = ?",
            (document_id, user.org_id),
        ).fetchone()
        if refreshed is None:
            raise LookupError("document metadata disappeared during review")
        _persist_receipt(
            connection,
            refreshed,
            root=Path(storage_root).resolve(),
            audit_event_id=event_id,
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return get_document_metadata(connection, user, document_id)


def retrieve_document(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    document_id: str,
    *,
    variant: str = "derivative",
    storage_root: Path | str = DEFAULT_STORAGE_ROOT,
) -> bytes:
    """Decrypt and hash-verify an approved original or derivative."""

    permission = "retrieve_original" if variant == "original" else "retrieve_derivative"
    if variant not in {"original", "derivative"}:
        raise ValueError("variant must be original or derivative")
    row = _require_document(connection, user, document_id, permission)
    if row["status"] != "approved":
        _audit_blocked(
            connection,
            request_id=document_id,
            actor=user.actor_id,
            action_type="document_retrieval",
            rule="privacy review required",
            reason="The document has not completed the required privacy review.",
        )
        raise AuthorizationError("document requires explicit privacy review before retrieval")
    relative = row["original_path"] if variant == "original" else row["derivative_path"]
    expected_digest = row["original_sha256"] if variant == "original" else row["derivative_sha256"]
    if not relative or not expected_digest:
        _audit_blocked(
            connection,
            request_id=document_id,
            actor=user.actor_id,
            action_type="document_retrieval",
            rule="requested derivative unavailable",
            reason="The requested document variant is not available for release.",
        )
        raise DocumentValidationError("the requested document derivative is unavailable")
    root = Path(storage_root).resolve()
    path = (root / relative).resolve()
    if root not in path.parents:
        raise StorageConfigurationError("stored document path escaped the private vault")
    try:
        encrypted = path.read_bytes()
        plaintext = decrypt_bytes(
            encrypted,
            aad=_aad(document_id, row["org_id"], variant),
        )
        if not hmac_compare(sha256_hex(plaintext), expected_digest):
            raise DocumentIntegrityError("stored document digest does not match metadata")
        _audit_document(
            connection,
            request_id=document_id,
            actor=user.actor_id,
            action_type="document_retrieved",
            decision="allowed",
            risk="low",
            rule=f"tenant-authorized {variant} retrieval",
            reason="Approved synthetic document decrypted and integrity-checked.",
            state_changed=False,
        )
        connection.commit()
        return plaintext
    except (OSError, sqlite3.Error, DecryptionError, DocumentIntegrityError, KeyConfigurationError) as exc:
        try:
            _audit_document(
                connection,
                request_id=document_id,
                actor=user.actor_id,
                action_type="document_retrieval_blocked",
                decision="blocked",
                risk="high",
                rule="document integrity or key verification failed",
                reason="The protected document could not be authenticated and was not returned.",
                state_changed=False,
            )
            connection.commit()
        except Exception:
            connection.rollback()
        if isinstance(exc, KeyConfigurationError):
            raise StorageConfigurationError("document key is unavailable; content was not returned") from None
        raise DocumentIntegrityError("document authentication or integrity verification failed") from None


def hmac_compare(left: str, right: str) -> bool:
    """Compare fixed-format digest strings without ordinary equality shortcuts."""

    import hmac

    return hmac.compare_digest(left, right)


def verify_document_integrity(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    document_id: str,
    *,
    storage_root: Path | str = DEFAULT_STORAGE_ROOT,
) -> dict[str, Any]:
    """Read-only integrity report for both encrypted variants."""

    row = _require_document(connection, user, document_id, "metadata")
    results: dict[str, Any] = {"document_id": document_id, "valid": True, "variants": {}}
    key = None
    try:
        key = load_document_key()
    except KeyConfigurationError:
        return {
            "document_id": document_id,
            "valid": False,
            "variants": {},
            "error": "document encryption key is unavailable",
        }
    invalid_variants: list[str] = []
    for variant in ("original", "derivative"):
        if not row[f"{variant}_path"]:
            results["variants"][variant] = {"available": False, "valid": False}
            results["valid"] = False
            continue
        try:
            root = Path(storage_root).resolve()
            path = (root / row[f"{variant}_path"]).resolve()
            if root not in path.parents:
                raise StorageConfigurationError("stored document path escaped the private vault")
            payload = decrypt_bytes(
                path.read_bytes(),
                aad=_aad(document_id, row["org_id"], variant),
                key=key,
            )
            digest = sha256_hex(payload)
            valid = hmac_compare(digest, row[f"{variant}_sha256"])
            results["variants"][variant] = {"available": True, "valid": valid, "sha256": digest if valid else None}
            if not valid:
                results["valid"] = False
        except (OSError, DecryptionError, DocumentIntegrityError, StorageConfigurationError):
            results["variants"][variant] = {"available": True, "valid": False}
            results["valid"] = False
            invalid_variants.append(variant)
    if invalid_variants:
        try:
            _audit_document(
                connection,
                request_id=document_id,
                actor=user.actor_id,
                action_type="document_integrity_failed",
                decision="blocked",
                risk="high",
                rule="document integrity verification failed",
                reason="Encrypted document content could not be authenticated or matched to its stored digest.",
                state_changed=False,
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return results


def verify_document_receipt(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    document_id: str,
    *,
    storage_root: Path | str = DEFAULT_STORAGE_ROOT,
) -> dict[str, Any]:
    """Verify a signed non-sensitive receipt and its referenced artifacts."""

    row = _require_document(connection, user, document_id, "metadata")
    result: dict[str, Any] = {
        "document_id": document_id,
        "valid": False,
        "signature_valid": False,
        "artifact_digests_match": False,
        "audit_event_present": False,
        "checkpoint_ref": None,
        "errors": [],
    }
    if not row["receipt_json"] or not row["receipt_signature"]:
        result["errors"].append("signed privacy receipt is missing")
        return result
    try:
        payload = json.loads(row["receipt_json"])
        if not isinstance(payload, dict):
            raise ValueError("receipt payload is not an object")
        result["checkpoint_ref"] = payload.get("checkpoint_ref")
        result["signature_valid"] = verify_receipt_signature(
            payload,
            row["receipt_signature"],
        )
        if not result["signature_valid"]:
            raise ValueError("receipt signature is invalid")
        if payload.get("document_id") != row["document_id"] or payload.get("org_id") != row["org_id"]:
            raise ValueError("receipt scope does not match the document")
        root = Path(storage_root).resolve()
        original_path = (root / row["original_path"]).resolve()
        derivative_path = (
            (root / row["derivative_path"]).resolve() if row["derivative_path"] else None
        )
        if root not in original_path.parents or (
            derivative_path is not None and root not in derivative_path.parents
        ):
            raise StorageConfigurationError("stored document path escaped the private vault")
        original_digest = _encrypted_file_digest(original_path)
        derivative_digest = (
            _encrypted_file_digest(derivative_path) if derivative_path is not None else None
        )
        result["artifact_digests_match"] = (
            payload.get("original_encrypted_sha256") == original_digest
            and payload.get("derivative_encrypted_sha256") == derivative_digest
        )
        if not result["artifact_digests_match"]:
            raise DocumentIntegrityError("receipt artifact digest does not match storage")
        audit_event_id = payload.get("audit_event_id")
        if not isinstance(audit_event_id, int):
            raise ValueError("receipt audit reference is invalid")
        result["audit_event_present"] = connection.execute(
            "SELECT 1 FROM audit_events WHERE id = ?",
            (audit_event_id,),
        ).fetchone() is not None
        if not result["audit_event_present"]:
            raise ValueError("receipt audit reference is missing")
        result["valid"] = True
    except (OSError, ReceiptConfigurationError, StorageConfigurationError, DocumentIntegrityError, TypeError, ValueError, json.JSONDecodeError) as exc:
        result["errors"].append(str(exc))
    if not result["valid"]:
        _audit_blocked(
            connection,
            request_id=document_id,
            actor=user.actor_id,
            action_type="document_receipt_verification",
            rule="privacy receipt verification failed",
            reason="The signed privacy receipt or its referenced evidence could not be verified.",
        )
    return result


def refresh_document_receipt(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    document_id: str,
    *,
    checkpoint_ref: str | None = None,
    storage_root: Path | str = DEFAULT_STORAGE_ROOT,
) -> dict[str, Any]:
    """Re-sign a receipt after an independently stored checkpoint is created."""

    row = _require_document(connection, user, document_id, "metadata")
    prior = json.loads(row["receipt_json"]) if row["receipt_json"] else {}
    _persist_receipt(
        connection,
        row,
        root=Path(storage_root).resolve(),
        audit_event_id=prior.get("audit_event_id"),
        checkpoint_ref=checkpoint_ref,
    )
    connection.commit()
    return get_document_metadata(connection, user, document_id)


def delete_document(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    document_id: str,
    *,
    storage_root: Path | str = DEFAULT_STORAGE_ROOT,
) -> None:
    """Request a recoverable deletion and retain a non-content tombstone."""

    row = _require_document(connection, user, document_id, "delete")
    root = Path(storage_root).resolve()
    paths = [root / row["original_path"]]
    if row["derivative_path"]:
        paths.append(root / row["derivative_path"])
    operation_id = f"DEL-{uuid.uuid4().hex}"
    requested_at = _utc_now()
    try:
        connection.execute(
            """
            UPDATE documents
            SET deletion_status = 'pending', deletion_operation_id = ?,
                deletion_requested_at = ?, updated_at = ?
            WHERE document_id = ? AND org_id = ? AND deletion_status = 'active'
            """,
            (operation_id, requested_at, requested_at, document_id, user.org_id),
        )
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise AuthorizationError("document deletion is already in progress")
        _audit_document(
            connection,
            request_id=operation_id,
            actor=user.actor_id,
            action_type="document_deletion_requested",
            decision="allowed",
            risk="medium",
            rule="organization admin deletion requested",
            reason="Synthetic document deletion entered a recoverable pending state.",
            state_changed=True,
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise

    try:
        for path in paths:
            resolved = path.resolve()
            if root not in resolved.parents:
                raise StorageConfigurationError("stored document path escaped the private vault")
            resolved.unlink(missing_ok=True)
    except Exception as exc:
        try:
            connection.execute(
                "UPDATE documents SET deletion_status = 'failed', processing_error = ?, updated_at = ? WHERE document_id = ?",
                ("Deletion requires reconciliation after a storage failure.", _utc_now(), document_id),
            )
            _audit_document(
                connection,
                request_id=operation_id,
                actor=user.actor_id,
                action_type="document_deletion_failed",
                decision="blocked",
                risk="high",
                rule="recoverable deletion failure",
                reason="Encrypted artifact deletion did not complete; reconciliation is required.",
                state_changed=False,
            )
            connection.commit()
        except Exception:
            connection.rollback()
        raise StorageConfigurationError("document deletion requires reconciliation") from exc

    try:
        connection.execute(
            """
            UPDATE documents
            SET deletion_status = 'deleted', deletion_completed_at = ?,
                processing_error = NULL, updated_at = ?
            WHERE document_id = ? AND deletion_status IN ('pending', 'failed')
            """,
            (_utc_now(), _utc_now(), document_id),
        )
        _audit_document(
            connection,
            request_id=operation_id,
            actor=user.actor_id,
            action_type="document_deleted",
            decision="allowed",
            risk="medium",
            rule="recoverable organization admin deletion completed",
            reason="Synthetic encrypted artifacts were removed and the metadata tombstone was retained.",
            state_changed=True,
        )
        connection.commit()
    except Exception as exc:
        connection.rollback()
        raise StorageConfigurationError("document deletion completed in storage but metadata needs reconciliation") from exc


def reconcile_deletions(
    connection: sqlite3.Connection,
    user: WorkspaceUser,
    *,
    storage_root: Path | str = DEFAULT_STORAGE_ROOT,
) -> list[str]:
    """Retry pending or failed deletions idempotently for an organization admin."""

    current = require_permission(connection, user, "delete")
    root = Path(storage_root).resolve()
    rows = connection.execute(
        "SELECT * FROM documents WHERE org_id = ? AND deletion_status IN ('pending', 'failed') ORDER BY document_id",
        (current.org_id,),
    ).fetchall()
    completed: list[str] = []
    for row in rows:
        paths = [root / row["original_path"]]
        if row["derivative_path"]:
            paths.append(root / row["derivative_path"])
        try:
            for path in paths:
                resolved = path.resolve()
                if root not in resolved.parents:
                    raise StorageConfigurationError("stored document path escaped the private vault")
                resolved.unlink(missing_ok=True)
            operation_id = row["deletion_operation_id"] or f"DEL-RECON-{uuid.uuid4().hex}"
            connection.execute(
                "UPDATE documents SET deletion_status = 'deleted', deletion_completed_at = ?, processing_error = NULL, updated_at = ? WHERE document_id = ?",
                (_utc_now(), _utc_now(), row["document_id"]),
            )
            _audit_document(
                connection,
                request_id=operation_id,
                actor=current.actor_id,
                action_type="document_deleted_reconciled",
                decision="allowed",
                risk="medium",
                rule="deletion reconciliation",
                reason="An interrupted synthetic document deletion was safely completed.",
                state_changed=True,
            )
            connection.commit()
            completed.append(row["document_id"])
        except Exception:
            connection.rollback()
            raise StorageConfigurationError("deletion reconciliation failed") from None
    return completed

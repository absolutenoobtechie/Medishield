"""Synthetic document privacy services for the MediShield local MVP."""

from .deid import DeidentificationResult, deidentify_text
from .vault import (
    DocumentIntegrityError,
    DocumentValidationError,
    StorageConfigurationError,
    get_document_metadata,
    reconcile_deletions,
    refresh_document_receipt,
    verify_document_receipt,
    upload_document,
)

__all__ = [
    "DeidentificationResult",
    "DocumentIntegrityError",
    "DocumentValidationError",
    "StorageConfigurationError",
    "deidentify_text",
    "get_document_metadata",
    "reconcile_deletions",
    "refresh_document_receipt",
    "upload_document",
    "verify_document_receipt",
]

"""Signed, non-sensitive provenance receipts for processed synthetic documents."""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


RECEIPT_SCHEMA = "medishield-privacy-receipt-v1"
PIPELINE_VERSION = "rule-based-deid-v1"
PRIVATE_KEY_ENV = "MEDISHIELD_RECEIPT_SIGNING_PRIVATE_KEY"
PUBLIC_KEY_ENV = "MEDISHIELD_RECEIPT_SIGNING_PUBLIC_KEY"
KEY_ID_ENV = "MEDISHIELD_RECEIPT_SIGNING_KEY_ID"


class ReceiptConfigurationError(ValueError):
    """Raised when receipt signing or verification configuration is unavailable."""


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
    raise ReceiptConfigurationError(f"{name} must encode exactly 32 key bytes")


def load_private_key() -> Ed25519PrivateKey:
    value = os.environ.get(PRIVATE_KEY_ENV)
    if not value:
        raise ReceiptConfigurationError(f"{PRIVATE_KEY_ENV} is required")
    return Ed25519PrivateKey.from_private_bytes(_decode_key(value, PRIVATE_KEY_ENV))


def load_public_key() -> Ed25519PublicKey:
    value = os.environ.get(PUBLIC_KEY_ENV)
    if not value:
        raise ReceiptConfigurationError(f"{PUBLIC_KEY_ENV} is required")
    return Ed25519PublicKey.from_public_bytes(_decode_key(value, PUBLIC_KEY_ENV))


def key_id() -> str:
    value = os.environ.get(KEY_ID_ENV)
    if not value or len(value) > 80 or any(ord(char) < 32 for char in value):
        raise ReceiptConfigurationError(f"{KEY_ID_ENV} is required")
    return value


def canonical_receipt(payload: Mapping[str, Any]) -> bytes:
    if payload.get("receipt_schema") != RECEIPT_SCHEMA:
        raise ValueError("receipt schema is invalid")
    return json.dumps(
        dict(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sign_receipt(payload: Mapping[str, Any]) -> str:
    signature = load_private_key().sign(canonical_receipt(payload))
    return base64.urlsafe_b64encode(signature).decode("ascii")


def verify_receipt_signature(
    payload: Mapping[str, Any],
    signature: str,
    public_key: Optional[Ed25519PublicKey] = None,
) -> bool:
    try:
        (public_key or load_public_key()).verify(
            base64.urlsafe_b64decode(signature.encode("ascii")),
            canonical_receipt(payload),
        )
        return True
    except (ReceiptConfigurationError, InvalidSignature, TypeError, ValueError):
        return False

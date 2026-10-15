"""Small cryptographic primitives for the synthetic document vault.

Keys are configuration, not application data.  Missing or malformed keys are
errors; this module intentionally has no development fallback secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyConfigurationError(ValueError):
    """Raised when a required document or pseudonym key is unavailable."""


class DecryptionError(ValueError):
    """Raised when an encrypted document cannot be authenticated or decoded."""


_ENVELOPE_PREFIX = b"MSD1"
_NONCE_BYTES = 12
_AES_KEY_BYTES = 32


def _load_32_byte_secret(name: str) -> bytes:
    raw = os.environ.get(name)
    if not raw:
        raise KeyConfigurationError(f"{name} is required for this protected operation")

    candidates: list[bytes] = []
    try:
        candidates.append(base64.urlsafe_b64decode(raw.encode("ascii")))
    except (ValueError, UnicodeError):
        pass
    try:
        candidates.append(bytes.fromhex(raw))
    except ValueError:
        pass
    candidates.append(raw.encode("utf-8"))
    for candidate in candidates:
        if len(candidate) == _AES_KEY_BYTES:
            return candidate
    raise KeyConfigurationError(f"{name} must encode exactly 32 bytes")


def load_document_key() -> bytes:
    """Load the AES-256-GCM key from ``MEDISHIELD_DOCUMENT_KEY``."""

    return _load_32_byte_secret("MEDISHIELD_DOCUMENT_KEY")


def load_pseudonym_secret() -> bytes:
    """Load the separate tenant pseudonymization secret."""

    return _load_32_byte_secret("MEDISHIELD_PSEUDONYM_SECRET")


def sha256_hex(data: bytes) -> str:
    """Return a content digest; this is not an authorization proof."""

    return hashlib.sha256(data).hexdigest()


def encrypt_bytes(plaintext: bytes, *, aad: bytes, key: bytes | None = None) -> bytes:
    """Encrypt bytes with fresh-nonce AES-256-GCM and authenticated metadata."""

    key_bytes = load_document_key() if key is None else key
    if len(key_bytes) != _AES_KEY_BYTES:
        raise KeyConfigurationError("document encryption key must be exactly 32 bytes")
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, aad)
    return _ENVELOPE_PREFIX + nonce + ciphertext


def decrypt_bytes(envelope: bytes, *, aad: bytes, key: bytes | None = None) -> bytes:
    """Authenticate and decrypt one vault envelope, failing closed on tampering."""

    key_bytes = load_document_key() if key is None else key
    if len(key_bytes) != _AES_KEY_BYTES:
        raise KeyConfigurationError("document encryption key must be exactly 32 bytes")
    if len(envelope) <= len(_ENVELOPE_PREFIX) + _NONCE_BYTES or not envelope.startswith(_ENVELOPE_PREFIX):
        raise DecryptionError("encrypted document envelope is malformed")
    nonce_start = len(_ENVELOPE_PREFIX)
    nonce = envelope[nonce_start:nonce_start + _NONCE_BYTES]
    ciphertext = envelope[nonce_start + _NONCE_BYTES:]
    try:
        return AESGCM(key_bytes).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise DecryptionError("encrypted document authentication failed") from None


def pseudonym_for(*, org_id: str, category: str, value: str, secret: bytes | None = None) -> str:
    """Create a stable, organization-scoped pseudonym using domain separation."""

    key = load_pseudonym_secret() if secret is None else secret
    if len(key) != _AES_KEY_BYTES:
        raise KeyConfigurationError("pseudonym secret must be exactly 32 bytes")
    message = f"medishield:pseudonym:v1:{org_id}:{category}:{value}".encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).hexdigest().upper()
    return f"[{category.upper()}_{digest[:12]}]"

"""Pytest fixtures and environment configuration for MediShield."""

import os
import secrets
import sys
import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Tests use an ephemeral gateway secret. Production configuration is supplied
# outside source control through MEDISHIELD_APPROVAL_SECRET.
os.environ.setdefault("MEDISHIELD_APPROVAL_SECRET", secrets.token_hex(32))
# Isolated keys for the synthetic document-vault tests.  Production code has
# no fallback and still fails closed when either configured key is absent.
os.environ.setdefault("MEDISHIELD_DOCUMENT_KEY", secrets.token_hex(32))
os.environ.setdefault("MEDISHIELD_PSEUDONYM_SECRET", secrets.token_hex(32))


def _set_ed25519_pair(private_name: str, public_name: str, key_id_name: str, key_id: str) -> None:
    if os.environ.get(private_name) and os.environ.get(public_name):
        return
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    os.environ.setdefault(private_name, base64.urlsafe_b64encode(private_bytes).decode("ascii"))
    os.environ.setdefault(public_name, base64.urlsafe_b64encode(public_bytes).decode("ascii"))
    os.environ.setdefault(key_id_name, key_id)


_set_ed25519_pair(
    "MEDISHIELD_RECEIPT_SIGNING_PRIVATE_KEY",
    "MEDISHIELD_RECEIPT_SIGNING_PUBLIC_KEY",
    "MEDISHIELD_RECEIPT_SIGNING_KEY_ID",
    "test-receipt-key",
)
_set_ed25519_pair(
    "MEDISHIELD_AUDIT_CHECKPOINT_PRIVATE_KEY",
    "MEDISHIELD_AUDIT_CHECKPOINT_PUBLIC_KEY",
    "MEDISHIELD_AUDIT_CHECKPOINT_KEY_ID",
    "test-checkpoint-key",
)

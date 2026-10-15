"""Trusted approval authentication helpers.

The action SHA-256 digest remains a content fingerprint.  This module adds a
gateway-controlled authentication tag over the complete approval record so a
caller cannot manufacture an approval by recomputing a public digest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from decimal import Decimal
from typing import Any

from .intent import canonicalize_action
from .policy import PINNED_DESTINATIONS


APPROVAL_SECRET_ENV = "MEDISHIELD_APPROVAL_SECRET"
MIN_APPROVAL_SECRET_BYTES = 32
DEFAULT_APPROVAL_TOOL = "update_order"
DEFAULT_APPROVAL_DESTINATION = PINNED_DESTINATIONS[DEFAULT_APPROVAL_TOOL]


class ApprovalAuthenticationError(RuntimeError):
    """Raised when the gateway cannot obtain a valid approval secret."""


def load_approval_secret() -> bytes:
    """Load the gateway secret, rejecting absent or weak configuration."""

    value = os.environ.get(APPROVAL_SECRET_ENV)
    if not isinstance(value, str) or not value:
        raise ApprovalAuthenticationError(
            f"{APPROVAL_SECRET_ENV} is required for approval authentication"
        )
    secret = value.encode("utf-8")
    if len(secret) < MIN_APPROVAL_SECRET_BYTES:
        raise ApprovalAuthenticationError(
            f"{APPROVAL_SECRET_ENV} must contain at least "
            f"{MIN_APPROVAL_SECRET_BYTES} UTF-8 bytes"
        )
    return secret


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("approval action JSON contains duplicate keys")
        result[key] = value
    return result


def parse_approval_action(action_json: str) -> Mapping[str, Any]:
    """Parse and revalidate persisted action JSON without accepting ambiguity."""

    if not isinstance(action_json, str):
        raise ValueError("approval action JSON must be text")
    try:
        parsed = json.loads(
            action_json,
            parse_float=Decimal,
            parse_int=Decimal,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("approval action JSON is invalid") from exc
    if not isinstance(parsed, Mapping):
        raise ValueError("approval action JSON must be an object")
    canonical = canonicalize_action(parsed)
    if not hmac.compare_digest(canonical, action_json):
        raise ValueError("approval action JSON is not canonical")
    return parsed


def _approval_payload(
    *,
    approval_id: str,
    action_json: str,
    action_hash: str,
    approver_id: str,
    created_at: str,
    expires_at: str,
    tool: str,
    destination: str,
) -> bytes:
    """Build deterministic bytes for the authenticated approval envelope."""

    action = parse_approval_action(action_json)
    payload = {
        "approval_id": approval_id,
        "action": action,
        "action_hash": action_hash,
        "approver_id": approver_id,
        "created_at": created_at,
        "expires_at": expires_at,
        "tool": tool,
        "destination": destination,
        "schema_version": "approval-v2",
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def compute_approval_mac(
    *,
    approval_id: str,
    action_json: str,
    action_hash: str,
    approver_id: str,
    created_at: str,
    expires_at: str,
    tool: str = DEFAULT_APPROVAL_TOOL,
    destination: str = DEFAULT_APPROVAL_DESTINATION,
) -> str:
    """Return the gateway-controlled MAC for the complete approval record."""

    return hmac.new(
        load_approval_secret(),
        _approval_payload(
            approval_id=approval_id,
            action_json=action_json,
            action_hash=action_hash,
            approver_id=approver_id,
            created_at=created_at,
            expires_at=expires_at,
            tool=tool,
            destination=destination,
        ),
        hashlib.sha256,
    ).hexdigest()

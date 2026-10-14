"""Clinical Intent Lock primitives."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Any

from .models import ProtectedAction


def _model_fields() -> tuple[str, ...]:
    fields = getattr(ProtectedAction, "model_fields", None)
    if fields is None:  # Pydantic v1 compatibility.
        fields = ProtectedAction.__fields__
    return tuple(fields)


_PROTECTED_FIELDS = _model_fields()


def _model_dump(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _validated_values(action: ProtectedAction | Mapping[str, Any]) -> dict[str, Any]:
    """Validate canonicalization input using the strict action contract."""

    try:
        if isinstance(action, ProtectedAction):
            if getattr(action, "model_extra", None):
                raise ValueError("protected action contains unexpected fields")
            raw = _model_dump(action)
        elif isinstance(action, Mapping):
            raw = dict(action)
        else:
            raise ValueError("protected action must be a model or mapping")

        if hasattr(ProtectedAction, "model_validate"):
            values = _model_dump(ProtectedAction.model_validate(raw))
        else:
            values = _model_dump(ProtectedAction.parse_obj(raw))
        if set(values) != set(_PROTECTED_FIELDS):
            raise ValueError("protected action fields do not match the contract")
        return values
    except (TypeError, ValueError) as exc:
        raise ValueError("protected action is invalid") from exc


MAX_DOSE_STRING_LENGTH = 64
MAX_DOSE_VALUE = Decimal("1000000")


def _normalize_dose(value: str) -> str:
    """Normalize a medication dose string into canonical decimal representation.

    Enforces fail-closed validation:
    - Input must be a string within reasonable length bounds (<=64 chars).
    - Value must be finite, strictly positive, and within clinical sanity limits (<=1,000,000).
    - Arithmetic and conversion errors are safely converted to ValueError.
    """
    if not isinstance(value, str):
        raise ValueError("dose must be a string")
    trimmed = value.strip()
    if not trimmed:
        raise ValueError("dose must not be empty")
    if len(trimmed) > MAX_DOSE_STRING_LENGTH:
        raise ValueError(
            f"dose string length ({len(trimmed)}) exceeds sanity bound of {MAX_DOSE_STRING_LENGTH}"
        )

    try:
        dose = Decimal(trimmed)
        if not dose.is_finite():
            raise ValueError("dose must be a finite decimal value")
        if dose <= 0:
            raise ValueError("dose must be a positive decimal value")
        if dose > MAX_DOSE_VALUE:
            raise ValueError(
                f"dose exceeds clinical sanity upper bound of {MAX_DOSE_VALUE}"
            )
        normalized = dose.normalize()
        return format(normalized, "f")
    except (ArithmeticError, InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("dose must be a valid, finite, positive decimal value") from exc


def canonicalize_action(action: ProtectedAction | Mapping[str, Any]) -> str:
    """Return sorted, compact JSON for the authoritative action fields only."""

    values = _validated_values(action)
    text_fields = (
        "patient_id",
        "medication_id",
        "units",
        "route",
        "frequency",
        "order_id",
    )
    for field in text_fields:
        if not isinstance(values[field], str) or not values[field].strip():
            raise ValueError(f"{field} must be a non-empty string")
    if values["duration"] is not None and (
        not isinstance(values["duration"], str) or not values["duration"].strip()
    ):
        raise ValueError("duration must be null or a non-empty string")
    canonical = {field: values[field] for field in _PROTECTED_FIELDS}
    canonical["dose"] = _normalize_dose(canonical["dose"])
    canonical["units"] = canonical["units"].lower()
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), allow_nan=False)


def action_hash(action: ProtectedAction | Mapping[str, Any]) -> str:
    """Return the SHA-256 hash recomputed from the canonical action."""

    return hashlib.sha256(canonicalize_action(action).encode("utf-8")).hexdigest()

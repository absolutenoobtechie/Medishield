"""Clinical Intent Lock primitives.

Implements canonicalization and hashing for protected clinical actions.
"""

from decimal import Decimal
import hashlib
import json
from typing import Union

from .models import ProtectedAction


def canonicalize_action(action: Union[ProtectedAction, dict]) -> str:
    """Return deterministic protected-action JSON for hashing.

    Serializes only the protected fields as sorted, compact JSON.
    Normalizes ``dose`` with ``Decimal`` and lowercase ``units``.
    """
    if isinstance(action, ProtectedAction):
        data = action.model_dump() if hasattr(action, "model_dump") else action.dict()
    else:
        data = dict(action)

    # Decimal-normalize dose
    raw_dose = str(data.get("dose", "")).strip()
    try:
        d = Decimal(raw_dose)
        if d == d.to_integral():
            dose = str(int(d))
        else:
            dose = str(d.normalize())
            if "e" in dose.lower():
                dose = format(d, "f").rstrip("0").rstrip(".")
    except Exception:
        dose = raw_dose

    # Lowercase units
    units = str(data.get("units", "")).strip().lower()

    # Protected fields only, alphabetical sorting
    protected_fields = {
        "dose": dose,
        "duration": data.get("duration"),
        "frequency": str(data.get("frequency", "")).strip(),
        "medication_id": str(data.get("medication_id", "")).strip(),
        "order_id": str(data.get("order_id", "")).strip(),
        "patient_id": str(data.get("patient_id", "")).strip(),
        "route": str(data.get("route", "")).strip(),
        "units": units,
    }

    return json.dumps(protected_fields, sort_keys=True, separators=(",", ":"))


def action_hash(action: Union[ProtectedAction, dict]) -> str:
    """Return the SHA-256 hash of the canonical protected action.

    Recomputes the digest from ``canonicalize_action(action)`` at the gateway.
    Never trusts a hash provided by an external AI agent.
    """
    canonical_json = canonicalize_action(action)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

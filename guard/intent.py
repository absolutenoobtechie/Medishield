"""Clinical Intent Lock primitives.

The team must implement the two functions in this file by hand.
"""

from .models import ProtectedAction


def canonicalize_action(action: ProtectedAction) -> str:
    """Return deterministic protected-action JSON for hashing.

    The implementation must serialize only the protected fields as sorted,
    compact JSON. It must normalize ``dose`` with ``Decimal`` and lowercase
    ``units``. It must reject unexpected fields and must never use a hash
    supplied by an AI agent. This scaffold intentionally does not implement
    those security rules yet.
    """

    raise NotImplementedError("The team must implement canonicalize_action by hand.")


def action_hash(action: ProtectedAction) -> str:
    """Return the hash of the canonical protected action.

    Recompute the digest from ``canonicalize_action(action)`` at the gateway;
    do not accept or reuse a digest supplied by the agent. This scaffold
    intentionally does not implement the hash yet.
    """

    raise NotImplementedError("The team must implement action_hash by hand.")

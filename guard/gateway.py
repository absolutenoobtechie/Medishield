"""Runtime decision point for execution requests."""

from .models import Decision, ExecutionRequest


def verify_execution(request: ExecutionRequest) -> Decision:
    """Verify an execution request before it can reach the backend.

    The team must implement the fail-closed check order from
    ``docs/CONTRACT.md``: validate schema and role, pin the tool and
    destination, validate the approval, recompute and compare the action hash,
    atomically consume the approval and write state, and audit every outcome.
    This scaffold intentionally does not implement those security rules yet.
    """

    raise NotImplementedError("The team must implement verify_execution by hand.")

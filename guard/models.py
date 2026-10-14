"""Pydantic contracts shared by the security gateway."""

from typing import Literal, Optional

from pydantic import BaseModel


class _StrictModel(BaseModel):
    """Base model that rejects fields not in the contract."""

    class Config:
        extra = "forbid"


class ProtectedAction(_StrictModel):
    patient_id: str
    medication_id: str
    dose: str
    units: str
    route: str
    frequency: str
    duration: Optional[str] = None
    order_id: str


class ExecutionRequest(_StrictModel):
    request_id: str
    actor_id: str
    tool: str
    approval_id: str
    action: ProtectedAction


class Decision(_StrictModel):
    decision: Literal["allowed", "blocked", "warning"]
    rule: str
    reason: str
    changed_fields: list[str]
    state_changed: bool

"""Policy evaluation and tool baseline rules for MediShield gateway."""

from typing import Dict, List, Optional, Set

# Permitted roles per MCP tool name
TOOL_PERMISSIONS: Dict[str, Set[str]] = {
    "update_order": {"agent", "clinician"},
    "read_patient_summary": {"agent", "clinician", "nurse"},
    "approve_action": {"clinician"},
    "cancel_order": {"clinician"},
    "dispense_simulated": {"clinician", "pharmacist"},
}

# Registered tool baseline destinations
PINNED_DESTINATIONS: Dict[str, str] = {
    "update_order": "backend://simulated-ehr/orders",
    "read_patient_summary": "backend://simulated-ehr/patients",
    "approve_action": "backend://simulated-ehr/approvals",
    "cancel_order": "backend://simulated-ehr/orders",
    "dispense_simulated": "backend://simulated-pharmacy/dispense",
}

# The SQLite baseline must contain this exact fingerprint for protected tools.
# This is a synthetic demo fingerprint, not a claim that every form of tool
# poisoning can be detected.
TOOL_BASELINE_FINGERPRINTS: Dict[str, str] = {
    "update_order": "sha256:medishield-demo-tool-v1",
}


def is_role_permitted(tool: str, role: str) -> bool:
    """Check if the given actor role is permitted to execute the tool."""
    allowed = TOOL_PERMISSIONS.get(tool)
    if allowed is None:
        # Unknown tool: fail closed
        return False
    return role.lower() in allowed


def is_destination_pinned(tool: str, destination: Optional[str] = None) -> bool:
    """Verify tool execution destination against baseline registry."""
    if tool not in PINNED_DESTINATIONS:
        return False
    if destination is None:
        return False
    return destination == PINNED_DESTINATIONS[tool]

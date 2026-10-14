"""MCP Trust Sentinel: Runtime integrity monitor for MCP tool registries in MediShield."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ==============================================================================
# SECTION 1: Authoritative Trusted MCP Tool Specifications
# ==============================================================================

TRUSTED_MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "get_patient_record",
        "description": "Retrieve synthetic patient medical record and clinical history by patient_id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "patient_id": {
                    "type": "string",
                    "description": "Synthetic patient identifier (e.g., P-101)",
                }
            },
            "required": ["patient_id"],
        },
    },
    {
        "name": "propose_medication_order",
        "description": "Propose a synthetic medication order for clinician review and cryptographic approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "order_id": {"type": "string", "description": "Synthetic order identifier"},
                "patient_id": {"type": "string", "description": "Patient identifier"},
                "medication_id": {"type": "string", "description": "Formulary medication identifier"},
                "dose": {"type": "string", "description": "Normalized dosage amount"},
                "units": {"type": "string", "description": "Normalized dosage units (e.g., mg, ml, units)"},
                "route": {"type": "string", "description": "Administration route (e.g., oral, iv)"},
                "frequency": {"type": "string", "description": "Dosing frequency (e.g., daily, bid)"},
                "duration": {"type": "string", "description": "Order duration (e.g., 7 days)"},
            },
            "required": [
                "order_id",
                "patient_id",
                "medication_id",
                "dose",
                "units",
                "route",
                "frequency",
            ],
        },
    },
    {
        "name": "request_clinician_approval",
        "description": "Submit a proposed clinical action hash to obtain an authorized clinician approval token.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action_hash": {
                    "type": "string",
                    "description": "SHA-256 intent hash of proposed action",
                },
                "approver_id": {
                    "type": "string",
                    "description": "Attending clinician identifier",
                },
            },
            "required": ["action_hash", "approver_id"],
        },
    },
    {
        "name": "execute_approved_order",
        "description": "Submit an execution request through the MediShield runtime security gateway.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "Unique execution request ID"},
                "actor_id": {"type": "string", "description": "Authorized actor ID (e.g., agent_1)"},
                "tool": {"type": "string", "description": "Target tool name"},
                "approval_id": {"type": "string", "description": "Clinician approval token ID"},
                "action": {"type": "object", "description": "Protected clinical action payload"},
            },
            "required": ["request_id", "actor_id", "tool", "approval_id", "action"],
        },
    },
    {
        "name": "get_security_events",
        "description": "Retrieve runtime security audit logs, intent verification outcomes, and forensic alerts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of audit events to retrieve (default: 50)",
                },
                "decision": {
                    "type": "string",
                    "description": "Optional filter by decision (allowed, blocked, warning)",
                },
            },
        },
    },
]


# ==============================================================================
# SECTION 2: Canonicalization & SHA-256 Fingerprint Functions
# ==============================================================================

def canonicalize_tool_definition(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Canonicalize a single tool definition for deterministic hashing.

    Sorts keys, strips excess whitespace, and normalizes schema types.
    """
    if not isinstance(tool, dict):
        raise ValueError(f"Invalid tool definition, expected dict: {type(tool)}")

    name = str(tool.get("name", "")).strip()
    if not name:
        raise ValueError("Tool definition missing required 'name' field")

    description = str(tool.get("description", "")).strip()
    schema = tool.get("inputSchema", {})
    if not isinstance(schema, dict):
        schema = {}

    return {
        "name": name,
        "description": description,
        "inputSchema": schema,
    }


def canonicalize_registry(tools: List[Dict[str, Any]]) -> str:
    """Return compact, sorted JSON serialization of a tool registry."""
    if not isinstance(tools, (list, tuple)):
        raise ValueError(f"Invalid tools collection, expected list: {type(tools)}")

    canonical_tools = []
    for t in tools:
        canonical_tools.append(canonicalize_tool_definition(t))

    # Sort tools strictly alphabetically by name for deterministic ordering
    canonical_tools.sort(key=lambda x: x["name"])

    return json.dumps(
        canonical_tools,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def compute_registry_fingerprint(tools: List[Dict[str, Any]]) -> str:
    """Compute the SHA-256 cryptographic digest of a canonical tool registry."""
    canonical_json = canonicalize_registry(tools)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


# Compute baseline fingerprint at module load time
EXPECTED_REGISTRY_FINGERPRINT = compute_registry_fingerprint(TRUSTED_MCP_TOOLS)
EXPECTED_TOOL_NAMES = [t["name"] for t in sorted(TRUSTED_MCP_TOOLS, key=lambda x: x["name"])]
EXPECTED_TOOLS_COUNT = len(TRUSTED_MCP_TOOLS)

# Previously reported benchmark fingerprint from documentation
PREVIOUS_BENCHMARK_FINGERPRINT = "5b90a5d5c8d8bc1566eadc3a4eab7ac56b81caded9c5f5f1ed0c0ed2a8a45091"


# ==============================================================================
# SECTION 3: Verification Result Data Model
# ==============================================================================

@dataclass
class ToolIntegrityDetail:
    name: str
    expected_presence: bool
    observed_presence: bool
    status: str  # "VERIFIED" | "MISSING" | "UNEXPECTED" | "RENAMED" | "SCHEMA_DRIFT" | "MALFORMED"
    schema_status: str  # "MATCH" | "MODIFIED" | "MISSING" | "N/A"
    metadata_status: str  # "MATCH" | "MODIFIED" | "N/A"
    description: str
    findings: str


@dataclass
class RegistryVerificationResult:
    status: str  # "TRUSTED" | "DRIFT DETECTED" | "VERIFICATION ERROR" | "RESTORED"
    expected_fingerprint: str
    observed_fingerprint: str
    fingerprints_match: bool
    expected_tools_count: int
    observed_tools_count: int
    expected_tools: List[str]
    observed_tools: List[str]
    missing_tools: List[str]
    unexpected_tools: List[str]
    modified_tools: List[str]
    differences: List[str]
    reason: str
    verification_errors: List[str]
    tool_details: List[ToolIntegrityDetail] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# SECTION 4: Trust Sentinel Registry Verification
# ==============================================================================

def get_trusted_baseline_tools() -> List[Dict[str, Any]]:
    """Return a deep copy of the authoritative trusted baseline tool registry."""
    return copy.deepcopy(TRUSTED_MCP_TOOLS)


def verify_registry(
    observed_tools: Optional[List[Dict[str, Any]]] = None,
    expected_tools: Optional[List[Dict[str, Any]]] = None,
) -> RegistryVerificationResult:
    """Verify an observed MCP tool registry against the trusted baseline.

    Detects:
      - Missing expected tools
      - Unexpected / rogue tools
      - Renamed tools
      - Schema drift or definition tampering
      - Cryptographic fingerprint divergence

    Fail-closed: Any mismatch or parse failure yields DRIFT DETECTED or VERIFICATION ERROR.
    """
    baseline = expected_tools if expected_tools is not None else TRUSTED_MCP_TOOLS
    expected_fp = compute_registry_fingerprint(baseline)
    expected_map = {t["name"]: t for t in baseline}
    expected_names = sorted(list(expected_map.keys()))

    if observed_tools is None:
        observed_tools = baseline

    differences: List[str] = []
    errors: List[str] = []
    tool_details: List[ToolIntegrityDetail] = []

    # Safe validation of observed registry structure
    if not isinstance(observed_tools, (list, tuple)):
        error_msg = f"Observed tools registry must be a list, got {type(observed_tools).__name__}"
        errors.append(error_msg)
        return RegistryVerificationResult(
            status="VERIFICATION ERROR",
            expected_fingerprint=expected_fp,
            observed_fingerprint="",
            fingerprints_match=False,
            expected_tools_count=len(expected_names),
            observed_tools_count=0,
            expected_tools=expected_names,
            observed_tools=[],
            missing_tools=expected_names,
            unexpected_tools=[],
            modified_tools=[],
            differences=[error_msg],
            reason=f"Registry verification failed: {error_msg}",
            verification_errors=errors,
            tool_details=[],
        )

    # Validate individual observed tools
    valid_observed: List[Dict[str, Any]] = []
    malformed_tools: List[str] = []
    for idx, t in enumerate(observed_tools):
        if not isinstance(t, dict):
            malformed_tools.append(f"item[{idx}] (type {type(t).__name__})")
            continue
        if "name" not in t or not str(t["name"]).strip():
            malformed_tools.append(f"item[{idx}] (missing name)")
            continue
        valid_observed.append(t)

    if malformed_tools:
        err = f"Malformed tool definitions detected: {', '.join(malformed_tools)}"
        errors.append(err)
        differences.append(err)

    try:
        observed_fp = compute_registry_fingerprint(valid_observed)
    except Exception as exc:
        err = f"Failed to compute observed registry fingerprint: {str(exc)}"
        errors.append(err)
        observed_fp = "MALFORMED_FINGERPRINT"

    observed_map = {t["name"]: t for t in valid_observed}
    observed_names = sorted(list(observed_map.keys()))

    missing_tools = [name for name in expected_names if name not in observed_map]
    unexpected_tools = [name for name in observed_names if name not in expected_map]
    modified_tools: List[str] = []

    # Check for renamed tools heuristically (e.g., similar schema or common prefix/suffix)
    renamed_pairs: Dict[str, str] = {}
    for m in missing_tools:
        for u in unexpected_tools:
            if m in u or u in m or "tamper" in u.lower():
                renamed_pairs[m] = u
                differences.append(
                    f"Possible renamed tool detected: expected '{m}' appears replaced by '{u}'"
                )

    # Check modified tools (present in both but content differs)
    for name in expected_names:
        if name in observed_map:
            exp_t = expected_map[name]
            obs_t = observed_map[name]

            exp_schema = exp_t.get("inputSchema", {})
            obs_schema = obs_t.get("inputSchema", {})
            schema_match = (
                json.dumps(exp_schema, sort_keys=True)
                == json.dumps(obs_schema, sort_keys=True)
            )

            exp_desc = exp_t.get("description", "").strip()
            obs_desc = obs_t.get("description", "").strip()
            desc_match = exp_desc == obs_desc

            if not schema_match or not desc_match:
                modified_tools.append(name)
                diff_parts = []
                if not schema_match:
                    diff_parts.append("inputSchema altered")
                if not desc_match:
                    diff_parts.append("description altered")
                differences.append(f"Tool '{name}' definition altered: {', '.join(diff_parts)}")

    # Record specific differences for missing and unexpected tools
    for m in missing_tools:
        if m not in renamed_pairs:
            differences.append(f"Expected tool '{m}' is missing from observed registry.")
    for u in unexpected_tools:
        if u not in renamed_pairs.values():
            differences.append(f"Unexpected tool '{u}' was detected in observed registry.")

    # Build detailed per-tool integrity breakdown
    all_known_names = sorted(list(set(expected_names + observed_names)))
    for name in all_known_names:
        is_exp = name in expected_map
        is_obs = name in observed_map

        if is_exp and is_obs:
            is_mod = name in modified_tools
            if is_mod:
                status = "SCHEMA_DRIFT"
                schema_status = "MODIFIED"
                meta_status = "MODIFIED"
                findings = f"Tool definition or schema altered from trusted baseline."
            else:
                status = "VERIFIED"
                schema_status = "MATCH"
                meta_status = "MATCH"
                findings = "Cryptographic schema and metadata match trusted baseline."
            desc = observed_map[name].get("description", expected_map[name].get("description", ""))
        elif is_exp and not is_obs:
            if name in renamed_pairs:
                status = "RENAMED"
                findings = f"Tool missing from registry (suspected rename to '{renamed_pairs[name]}')."
            else:
                status = "MISSING"
                findings = "Expected tool is completely missing from observed registry."
            schema_status = "MISSING"
            meta_status = "MISSING"
            desc = expected_map[name].get("description", "")
        else:  # is_obs and not is_exp
            status = "UNEXPECTED"
            schema_status = "N/A"
            meta_status = "N/A"
            findings = "Unapproved tool introduced into registry without authorization."
            desc = observed_map[name].get("description", "Unregistered external tool")

        tool_details.append(
            ToolIntegrityDetail(
                name=name,
                expected_presence=is_exp,
                observed_presence=is_obs,
                status=status,
                schema_status=schema_status,
                metadata_status=meta_status,
                description=desc,
                findings=findings,
            )
        )

    # Determine overall status and reason
    fps_match = bool(
        hmac.compare_digest(expected_fp, observed_fp)
        and observed_fp != "MALFORMED_FINGERPRINT"
    )

    if errors:
        status = "VERIFICATION ERROR"
        reason = f"Verification error: {'; '.join(errors)}"
    elif not fps_match or missing_tools or unexpected_tools or modified_tools:
        status = "DRIFT DETECTED"
        reasons = []
        if missing_tools:
            reasons.append(f"{len(missing_tools)} missing tool(s)")
        if unexpected_tools:
            reasons.append(f"{len(unexpected_tools)} unexpected tool(s)")
        if modified_tools:
            reasons.append(f"{len(modified_tools)} modified tool(s)")
        if not fps_match:
            reasons.append("SHA-256 fingerprint mismatch")
        reason = f"Registry drift detected: {', '.join(reasons)}."
    else:
        status = "TRUSTED"
        reason = "Tool registry matches authoritative baseline. All 5 tools verified."

    return RegistryVerificationResult(
        status=status,
        expected_fingerprint=expected_fp,
        observed_fingerprint=observed_fp,
        fingerprints_match=fps_match,
        expected_tools_count=len(expected_names),
        observed_tools_count=len(observed_names),
        expected_tools=expected_names,
        observed_tools=observed_names,
        missing_tools=missing_tools,
        unexpected_tools=unexpected_tools,
        modified_tools=modified_tools,
        differences=differences,
        reason=reason,
        verification_errors=errors,
        tool_details=tool_details,
    )

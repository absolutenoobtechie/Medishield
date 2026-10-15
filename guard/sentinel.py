"""MCP tool-registry integrity checks for the synthetic MediShield gateway.

The expected registry is intentionally explicit and versioned with the source.
It is not learned from the runtime registry. Updating it is a code-review
operation; drift never updates it automatically.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import math
from dataclasses import dataclass
from typing import Any, Mapping, Optional


class RegistryInspectionError(RuntimeError):
    """Raised when the installed MCP registry cannot be inspected safely."""


_PROTECTED_ACTION_SCHEMA = {
    "additionalProperties": False,
    "properties": {
        "patient_id": {"type": "string"},
        "medication_id": {"type": "string"},
        "dose": {"type": "string"},
        "units": {"type": "string"},
        "route": {"type": "string"},
        "frequency": {"type": "string"},
        "duration": {
            "anyOf": [{"type": "string"}, {"type": "null"}],
            "default": None,
        },
        "order_id": {"type": "string"},
    },
    "required": [
        "patient_id",
        "medication_id",
        "dose",
        "units",
        "route",
        "frequency",
        "order_id",
    ],
    "type": "object",
}


def _object_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"properties": properties, "type": "object"}
    if required:
        schema["required"] = required
    return schema


def _action_argument_schema() -> dict[str, Any]:
    return {
        "$defs": {"ProtectedAction": _PROTECTED_ACTION_SCHEMA},
        "properties": {"action": {"$ref": "#/$defs/ProtectedAction"}},
        "required": ["action"],
        "type": "object",
    }


def _action_schema_with_properties(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    schema = _action_argument_schema()
    schema["properties"] = properties
    schema["required"] = required
    return schema


# This is the reviewed expected declared registry for the currently supported
# MCP SDK line used by the project. It is deliberately not derived from mcp.
EXPECTED_TOOL_REGISTRY: tuple[dict[str, Any], ...] = (
    {
        "name": "get_patient_record",
        "title": None,
        "description": "Return one synthetic patient and that patient's synthetic orders.",
        "inputSchema": _object_schema(
            {"patient_id": {"type": "string"}}, ["patient_id"]
        ),
        "outputSchema": {"additionalProperties": True, "type": "object"},
        "annotations": None,
        "icons": None,
        "meta": None,
    },
    {
        "name": "propose_medication_order",
        "title": None,
        "description": "Validate and return a medication-order proposal without changing state.",
        "inputSchema": _action_argument_schema(),
        "outputSchema": {"additionalProperties": True, "type": "object"},
        "annotations": None,
        "icons": None,
        "meta": None,
    },
    {
        "name": "request_clinician_approval",
        "title": None,
        "description": "Create an approval only from a server-authenticated clinician context.",
        "inputSchema": _action_schema_with_properties(
            {
                "action": {"$ref": "#/$defs/ProtectedAction"},
                "approver_id": {"type": "string"},
                "ttl_minutes": {"type": "number"},
            },
            ["action", "approver_id", "ttl_minutes"],
        ),
        "outputSchema": {"additionalProperties": True, "type": "object"},
        "annotations": None,
        "icons": None,
        "meta": None,
    },
    {
        "name": "execute_approved_order",
        "title": None,
        "description": inspect.cleandoc(
            """
            Ask the security gateway to verify and execute one approved order.

            This tool constructs the execution request and delegates all protected
            execution to ``verify_execution``. It never calls the backend directly.
            """
        ).strip(),
        "inputSchema": _action_schema_with_properties(
            {
                "request_id": {"type": "string"},
                "actor_id": {"type": "string"},
                "approval_id": {"type": "string"},
                "action": {"$ref": "#/$defs/ProtectedAction"},
                "destination": {
                    "anyOf": [{"type": "string"}, {"type": "null"}],
                    "default": None,
                },
            },
            ["request_id", "actor_id", "approval_id", "action"],
        ),
        "outputSchema": {"additionalProperties": True, "type": "object"},
        "annotations": None,
        "icons": None,
        "meta": None,
    },
    {
        "name": "get_security_events",
        "title": None,
        "description": "Return security events visible to the authenticated audit role.",
        "inputSchema": _object_schema({"limit": {"type": "integer", "default": 20}}),
        "outputSchema": {
            "properties": {
                "result": {
                    "items": {"additionalProperties": True, "type": "object"},
                    "type": "array",
                }
            },
            "required": ["result"],
            "type": "object",
        },
        "annotations": None,
        "icons": None,
        "meta": None,
    },
)


@dataclass(frozen=True)
class TrustResult:
    """Structured result of one declared-registry verification."""

    status: str
    expected_fingerprint: Optional[str]
    observed_fingerprint: Optional[str]
    differences: list[str]
    explanation: str
    protected_execution_allowed: bool

    @property
    def reason(self) -> str:
        """Compatibility alias for callers using the dashboard-facing name."""

        return self.explanation

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "expected_fingerprint": self.expected_fingerprint,
            "observed_fingerprint": self.observed_fingerprint,
            "differences": list(self.differences),
            "explanation": self.explanation,
            "reason": self.explanation,
            "protected_execution_allowed": self.protected_execution_allowed,
        }


def _json_safe(value: Any) -> Any:
    """Convert SDK model values to JSON values or reject them."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RegistryInspectionError("registry metadata contains a non-finite number")
        return value
    if hasattr(value, "model_dump"):
        return _json_safe(value.model_dump())
    if hasattr(value, "dict") and callable(value.dict):
        return _json_safe(value.dict())
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    raise RegistryInspectionError("registry metadata is not JSON serializable")


def _canonical_schema(value: Any) -> Any:
    """Keep schema semantics while ignoring SDK-generated title noise."""

    if isinstance(value, Mapping):
        return {
            str(key): _canonical_schema(item)
            for key, item in value.items()
            if key != "title"
        }
    if isinstance(value, list):
        return [_canonical_schema(item) for item in value]
    return value


def _definition_value(definition: Any, field: str, alternate: str | None = None) -> Any:
    if isinstance(definition, Mapping):
        if field in definition:
            return definition[field]
        if alternate is not None:
            return definition.get(alternate)
        return None
    value = getattr(definition, field, None)
    if value is None and alternate is not None:
        value = getattr(definition, alternate, None)
    return value


def canonicalize_registry(registry: Any) -> list[dict[str, Any]]:
    """Return normalized tool declarations sorted by tool name.

    The input may be a list of FastMCP Tool objects or dictionaries with the
    same declared fields. It is read-only and never modifies the source.
    """

    if not isinstance(registry, (list, tuple)):
        raise RegistryInspectionError("tool registry must be a list")

    normalized: list[dict[str, Any]] = []
    names: set[str] = set()
    for definition in registry:
        name = _definition_value(definition, "name")
        description = _definition_value(definition, "description")
        input_schema = _definition_value(definition, "inputSchema", "parameters")
        output_schema = _definition_value(definition, "outputSchema", "output_schema")
        if not isinstance(name, str) or not name:
            raise RegistryInspectionError("tool registry contains a missing or invalid name")
        if name in names:
            raise RegistryInspectionError(f"tool registry contains duplicate tool: {name}")
        if not isinstance(description, str):
            raise RegistryInspectionError(f"tool has invalid description: {name}")
        if not isinstance(input_schema, Mapping):
            raise RegistryInspectionError(f"tool has no valid input schema: {name}")
        if not isinstance(output_schema, Mapping):
            raise RegistryInspectionError(f"tool has no valid output schema: {name}")
        names.add(name)
        normalized.append(
            {
                "name": name,
                "title": _json_safe(_definition_value(definition, "title")),
                "description": inspect.cleandoc(description).strip(),
                "inputSchema": _canonical_schema(_json_safe(input_schema)),
                "outputSchema": _canonical_schema(_json_safe(output_schema)),
                "annotations": _json_safe(_definition_value(definition, "annotations")),
                "icons": _json_safe(_definition_value(definition, "icons")),
                "meta": _json_safe(_definition_value(definition, "meta")),
            }
        )
    return sorted(normalized, key=lambda item: item["name"])


def registry_json(registry: Any) -> str:
    """Return deterministic compact JSON for a declared registry."""

    return json.dumps(
        canonicalize_registry(registry),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )

def registry_fingerprint(registry: Any) -> str:
    """Return the SHA-256 fingerprint of a canonical declared registry."""

    return hashlib.sha256(registry_json(registry).encode("utf-8")).hexdigest()


def inspect_fastmcp_registry(fastmcp_server: Any) -> list[Any]:
    """Read the installed FastMCP ToolManager registry without executing tools."""

    try:
        manager = getattr(fastmcp_server, "_tool_manager")
        list_tools = getattr(manager, "list_tools")
        tools = list_tools()
        if not isinstance(tools, list):
            raise RegistryInspectionError("FastMCP returned an invalid tool listing")
        return tools
    except RegistryInspectionError:
        raise
    except Exception as exc:
        raise RegistryInspectionError("FastMCP tool registry could not be inspected") from exc


def inspect_runtime_registry() -> list[Any]:
    """Inspect this server's registered FastMCP tools lazily to avoid import cycles."""

    try:
        from server import mcp_server

        return inspect_fastmcp_registry(mcp_server.mcp)
    except RegistryInspectionError:
        raise
    except Exception as exc:
        raise RegistryInspectionError("runtime MCP tool registry could not be inspected") from exc


def _context(result: TrustResult) -> str:
    return json.dumps(
        {
            "expected_fingerprint": result.expected_fingerprint,
            "observed_fingerprint": result.observed_fingerprint,
            "differences": result.differences,
            "status": result.status,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
def audit_reason(result: TrustResult) -> str:
    """Add concise machine-readable sentinel context to a human explanation."""

    return f"{result.explanation} (sentinel_context={_context(result)})"


def _differences(expected: list[dict[str, Any]], observed: list[dict[str, Any]]) -> list[str]:
    expected_by_name = {item["name"]: item for item in expected}
    observed_by_name = {item["name"]: item for item in observed}
    missing = sorted(set(expected_by_name) - set(observed_by_name))
    unexpected = sorted(set(observed_by_name) - set(expected_by_name))
    differences = [f"missing tool: {name}" for name in missing]
    differences.extend(f"unexpected tool: {name}" for name in unexpected)
    if missing and len(missing) == len(unexpected):
        differences.extend(
            f"renamed tool candidate: {old} -> {new}"
            for old, new in zip(missing, unexpected)
        )

    for name in sorted(set(expected_by_name) & set(observed_by_name)):
        expected_item = expected_by_name[name]
        observed_item = observed_by_name[name]
        if expected_item["inputSchema"] != observed_item["inputSchema"]:
            differences.append(f"changed input schema: {name}")
        if expected_item["outputSchema"] != observed_item["outputSchema"]:
            differences.append(f"changed output schema: {name}")
        for field in ("title", "description", "annotations", "icons", "meta"):
            if expected_item[field] != observed_item[field]:
                differences.append(f"changed interface metadata: {name}.{field}")
    return differences


def check_registry(observed_registry: Any = None) -> TrustResult:
    """Compare an observed MCP registry with the explicit trusted baseline."""

    try:
        expected = canonicalize_registry(EXPECTED_TOOL_REGISTRY)
        expected_fingerprint = registry_fingerprint(expected)
    except Exception:
        return TrustResult(
            status="baseline_invalid",
            expected_fingerprint=None,
            observed_fingerprint=None,
            differences=["missing or malformed trusted registry baseline"],
            explanation="The trusted MCP tool registry baseline is missing or malformed.",
            protected_execution_allowed=False,
        )

    try:
        raw_observed = inspect_runtime_registry() if observed_registry is None else observed_registry
        observed = canonicalize_registry(raw_observed)
        observed_fingerprint = registry_fingerprint(observed)
    except Exception:
        return TrustResult(
            status="unverifiable",
            expected_fingerprint=expected_fingerprint,
            observed_fingerprint=None,
            differences=["MCP tool registry inspection failed or returned malformed data"],
            explanation="The declared MCP tool registry could not be verified safely.",
            protected_execution_allowed=False,
        )

    differences = _differences(expected, observed)
    if not differences and hmac.compare_digest(expected_fingerprint, observed_fingerprint):
        return TrustResult(
            status="trusted",
            expected_fingerprint=expected_fingerprint,
            observed_fingerprint=observed_fingerprint,
            differences=[],
            explanation="The declared MCP tool registry matches the trusted baseline.",
            protected_execution_allowed=True,
        )

    difference_text = "; ".join(differences) or "registry fingerprint mismatch"
    return TrustResult(
        status="drift",
        expected_fingerprint=expected_fingerprint,
        observed_fingerprint=observed_fingerprint,
        differences=differences or ["registry fingerprint mismatch"],
        explanation=f"MCP tool registry drift detected: {difference_text}.",
        protected_execution_allowed=False,
    )


import copy
from dataclasses import asdict, field
from datetime import datetime, timezone

TRUSTED_MCP_TOOLS = list(EXPECTED_TOOL_REGISTRY)


def compute_registry_fingerprint(tools: Any) -> str:
    return registry_fingerprint(tools)


EXPECTED_REGISTRY_FINGERPRINT = registry_fingerprint(EXPECTED_TOOL_REGISTRY)
PREVIOUS_BENCHMARK_FINGERPRINT = "5b90a5d5c8d8bc1566eadc3a4eab7ac56b81caded9c5f5f1ed0c0ed2a8a45091"


@dataclass
class ToolIntegrityDetail:
    name: str
    expected_presence: bool
    observed_presence: bool
    status: str
    schema_status: str
    metadata_status: str
    description: str
    findings: str


@dataclass
class RegistryVerificationResult:
    status: str
    expected_fingerprint: str
    observed_fingerprint: str
    fingerprints_match: bool
    expected_tools_count: int
    observed_tools_count: int
    expected_tools: list[str]
    observed_tools: list[str]
    missing_tools: list[str]
    unexpected_tools: list[str]
    modified_tools: list[str]
    differences: list[str]
    reason: str
    verification_errors: list[str]
    tool_details: list[ToolIntegrityDetail] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def get_trusted_baseline_tools() -> list[dict[str, Any]]:
    return copy.deepcopy(list(TRUSTED_MCP_TOOLS))


def verify_registry(
    observed_tools: Optional[list[dict[str, Any]]] = None,
    expected_tools: Optional[list[dict[str, Any]]] = None,
) -> RegistryVerificationResult:
    """Build the dashboard-facing report from the live registry by default."""

    baseline = expected_tools if expected_tools is not None else TRUSTED_MCP_TOOLS
    expected_fp = compute_registry_fingerprint(baseline)
    expected_map = {t["name"]: t for t in baseline}
    expected_names = sorted(list(expected_map.keys()))

    if observed_tools is None:
        try:
            observed_tools = canonicalize_registry(inspect_runtime_registry())
        except Exception as exc:
            error_msg = f"Unable to inspect the live MCP registry: {exc}"
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
                verification_errors=[error_msg],
                tool_details=[],
            )

    differences: list[str] = []
    errors: list[str] = []
    tool_details: list[ToolIntegrityDetail] = []

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

    valid_observed: list[dict[str, Any]] = []
    malformed_tools: list[str] = []
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

    canonical_observed: list[dict[str, Any]] = []
    for item in valid_observed:
        try:
            canonical_observed.append(canonicalize_registry([item])[0])
        except Exception as exc:
            # An unexpected tool with an incomplete declaration is still
            # observable registry drift. Expected tools remain a verification
            # error when their declaration cannot be canonicalized.
            name = str(item.get("name", ""))
            fallback = {
                "name": name,
                "title": item.get("title"),
                "description": str(item.get("description", "")).strip(),
                "inputSchema": item.get("inputSchema", {})
                if isinstance(item.get("inputSchema", {}), Mapping)
                else {},
                "outputSchema": item.get("outputSchema", {})
                if isinstance(item.get("outputSchema", {}), Mapping)
                else {},
                "annotations": item.get("annotations"),
                "icons": item.get("icons"),
                "meta": item.get("meta"),
            }
            canonical_observed.append(fallback)
            if name in expected_map:
                errors.append(f"Failed to canonicalize expected tool {name}: {exc}")
            else:
                differences.append(f"Malformed unexpected tool definition: {name}")

    valid_observed = sorted(canonical_observed, key=lambda item: item["name"])
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
    modified_tools: list[str] = []

    renamed_pairs: dict[str, str] = {}
    for m in missing_tools:
        for u in unexpected_tools:
            if m in u or u in m or "tamper" in u.lower():
                renamed_pairs[m] = u
                differences.append(
                    f"Possible renamed tool detected: expected '{m}' appears replaced by '{u}'"
                )

    for name in expected_names:
        if name in observed_map:
            exp_t = expected_map[name]
            obs_t = observed_map[name]
            exp_schema = exp_t.get("inputSchema", {})
            obs_schema = obs_t.get("inputSchema", {})
            exp_output_schema = exp_t.get("outputSchema", {})
            obs_output_schema = obs_t.get("outputSchema", {})
            schema_match = json.dumps(exp_schema, sort_keys=True) == json.dumps(
                obs_schema, sort_keys=True
            )
            output_schema_match = json.dumps(
                exp_output_schema, sort_keys=True
            ) == json.dumps(obs_output_schema, sort_keys=True)
            exp_desc = exp_t.get("description", "").strip()
            obs_desc = obs_t.get("description", "").strip()
            desc_match = exp_desc == obs_desc
            metadata_match = all(
                exp_t.get(field) == obs_t.get(field)
                for field in ("title", "annotations", "icons", "meta")
            )

            if not schema_match or not output_schema_match or not desc_match or not metadata_match:
                modified_tools.append(name)
                diff_parts = []
                if not schema_match:
                    diff_parts.append("inputSchema altered")
                if not output_schema_match:
                    diff_parts.append("outputSchema altered")
                if not desc_match:
                    diff_parts.append("description altered")
                if not metadata_match:
                    diff_parts.append("interface metadata altered")
                differences.append(f"Tool '{name}' definition altered: {', '.join(diff_parts)}")

    for m in missing_tools:
        if m not in renamed_pairs:
            differences.append(f"Expected tool '{m}' is missing from observed registry.")
    for u in unexpected_tools:
        if u not in renamed_pairs.values():
            differences.append(f"Unexpected tool '{u}' was detected in observed registry.")

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
                findings = "Tool definition or schema altered from trusted baseline."
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
        else:
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

# End of the explicit reviewed registry verifier.

# The file intentionally ends after the reviewed verifier.

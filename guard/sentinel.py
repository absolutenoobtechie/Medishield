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
        "description": "Create a clinician approval for the exact validated protected action.",
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
        "description": "Return the newest synthetic security audit events.",
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "expected_fingerprint": self.expected_fingerprint,
            "observed_fingerprint": self.observed_fingerprint,
            "differences": list(self.differences),
            "explanation": self.explanation,
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

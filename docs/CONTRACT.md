# MediShield contract

MediShield is a synthetic hackathon prototype. The contract below defines the
data shape and security checks shared by the gateway, backend, MCP wrapper, and
dashboard.

## Protected action

`ProtectedAction` has exactly these fields and rejects extras:

`patient_id`, `medication_id`, `dose`, `units`, `route`, `frequency`,
`duration`, and `order_id`.

`dose` is a string. Canonicalization trims and normalizes it as a finite,
positive decimal, rejects values over `1,000,000`, and rejects input longer than
64 characters. `units` is lowercased in the canonical form. Other required text
fields must be non-empty.

## Audit event format

Every execution outcome should produce one event when the audit store is
available, including blocked and malformed requests. The JSONL event fields
are:

| Field | Allowed values or meaning |
| --- | --- |
| `time` | UTC timestamp with an offset or `Z` |
| `request_id` | Request identifier |
| `actor` | Actor identifier |
| `tool` | MCP-facing or policy tool name used by the request |
| `action_type` | Requested operation |
| `approval_id` | Approval identifier, when present |
| `decision` | `allowed`, `blocked`, or `warning` |
| `risk` | `low`, `medium`, or `high` |
| `rule` | Rule that produced the decision |
| `reason` | Plain-language explanation |
| `changed_fields` | List of protected fields that changed |
| `state_changed` | `true` or `false` |

The SQLite table stores the same event, with `actor` stored as `actor_id`,
`changed_fields` stored as JSON text, and `state_changed` stored as `0` or `1`.
The SQLite write and JSONL append are not one atomic cross-system operation;
file or database errors are propagated and the gateway fails closed.

## Tables

- `actors(actor_id, role)`
- `patients(patient_id, name_synthetic)`
- `approvals(approval_id, action_hash, action_json, approver_id, created_at, expires_at, revoked, consumed)`
- `orders(order_id, patient_id, medication_id, dose, units, route, frequency, duration)`
- `audit_events(id, time, request_id, actor_id, tool, action_type, approval_id, decision, risk, rule, reason, changed_fields, state_changed)`
- `tool_baseline(tool_name, fingerprint, allowed_destination)`

The default database is `medishield.sqlite3` at the repository root. Tests may
inject a temporary path or an open SQLite connection.

## MCP Trust Sentinel

`guard/sentinel.py` holds an explicit reviewed registry baseline for the five
FastMCP tools. It fingerprints each tool's name, normalized input schema,
output schema, description, title, annotations, icons, and metadata using
sorted compact JSON and SHA-256. SDK-generated schema titles are ignored; input
and output defaults and structural schema fields are retained. The baseline is
never learned from the currently observed registry and is never overwritten
automatically.

The result has `status`, `expected_fingerprint`, `observed_fingerprint`,
`differences`, `explanation`, and `protected_execution_allowed`. A missing or
malformed baseline, failed inspection, missing/extra/renamed tool, schema
change, or interface-metadata change is not eligible for protected execution.
The sentinel diagnoses declared registry drift only; a matching declaration
does not prove the Python callable behind a FastMCP tool, its dependencies, or a
remote server is safe. The current prototype does not hash or otherwise verify
callable source or bytecode.

## `verify_execution` check order

The gateway checks, in this order:

1. Validate the request schema and all protected fields.
2. Inspect and verify the declared MCP registry with the Trust Sentinel.
3. Validate the actor's role.
4. Pin the policy tool, the SQLite tool baseline, its fingerprint, and its exact destination.
5. Validate that the approval exists, is unexpired, is not revoked, is not consumed, and was issued by a clinician.
6. Recompute the protected-action hash and compare it with the stored approval hash.
7. Atomically consume the approval, write the order through `apply_order`, and write the audit event.
8. Audit every outcome that can be persisted safely.
9. Fail closed whenever a check, backend write, or audit write cannot be completed safely.

The MCP tool `execute_approved_order` always uses the policy name
`update_order` and delegates to `verify_execution`; it does not write the
`orders` table directly.

Registry drift blocks before approval consumption or order mutation. The block
reason carries compact sentinel context so the forensic reader can report the
expected and observed fingerprints without copying patient or action data.

## Dashboard Integration Contract

The dashboard connects directly to the backend security boundary without duplicating security logic or implementing frontend-only blocks:

### 1. Checking Registry Trust Status
```python
from server.mcp_server import get_tool_integrity_status

status = get_tool_integrity_status()
# Returns:
# {
#     "status": "trusted" | "drift" | "baseline_invalid" | "unverifiable",
#     "expected_fingerprint": "...",
#     "observed_fingerprint": "...",
#     "differences": ["unexpected tool: ..."],
#     "explanation": "...",
#     "protected_execution_allowed": True | False
# }
```

### 2. Runtime Tampering & Baseline Restoration
```python
from server.mcp_server import tamper_runtime_registry, restore_runtime_registry

# Inject synthetic tool to demonstrate drift in live server:
drift_status = tamper_runtime_registry("unexpected_tool", "Demonstration tool")

# Restore live server back to trusted 5-tool baseline:
clean_status = restore_runtime_registry()
```

### 3. Isolated Tampering Demonstration Scenario
```python
from demo.attacks import tool_registry_tampering

demo_result = tool_registry_tampering()
# Returns:
# {
#     "simulated_registry": { ... },
#     "blocked": {
#         "decision": "blocked",
#         "rule": "tool registry drift",
#         "state_changed": False,
#         "approval_consumed": False,
#         "handler_invoked": False,  # Proves protected handler was NOT called
#         "handler_calls": 0,
#         "evidence": { ... }        # Structured incident evidence
#     },
#     "restored": {
#         "registry": { ... },
#         "decision": "allowed",
#         "state_changed": True,
#         "approval_consumed": True
#     }
# }
```

### 4. Protected Execution & Patient Data Retrieval
```python
from server.mcp_server import get_patient_record, execute_approved_order

# Protected patient retrieval (fails closed with PermissionError on drift):
try:
    patient_data = get_patient_record(patient_id="P-104")
except PermissionError as exc:
    # Denied before database record was accessed

# Protected order execution:
decision = execute_approved_order(
    request_id="REQ-001",
    actor_id="agent_1",
    approval_id="APR-001",
    action=action,
)
```

### 5. Retrieving Structured Forensic Evidence
```python
from guard.forensics import evidence_for_request

evidence = evidence_for_request("REQ-001")
# Returns:
# {
#     "incident_id": "INC-000001",
#     "event_id": 1,
#     "time": "2026-10-14T08:00:00Z",
#     "request_id": "REQ-001",
#     "actor": "agent_1",
#     "tool": "update_order",
#     "failed_check": "tool registry drift",
#     "expected_fingerprint": "...",
#     "observed_fingerprint": "...",
#     "differences": ["unexpected tool: ..."],
#     "decision": "blocked",
#     "explanation": "...",
#     "state_changed": False,
#     "audit_event_refs": [1],
#     "is_simulation": True | False,
#     "evidence_type": "simulated_attack" | "runtime_security_event"
# }
```

### 6. Audit Trail Tamper & Integrity Verification
```python
from guard.forensics import verify_audit_integrity

integrity_report = verify_audit_integrity()
# Returns:
# {
#     "valid": True | False,
#     "tampering_detected": True | False,
#     "tampering_type": "modification" | "deletion" | "reordering" | None,
#     "record_count": 42,
#     "chain_digest": "...",
#     "errors": [],
#     "cross_store_verified": True | False
# }
```

## Folder ownership

- Person 1 owns `guard/`.
- Person 2 owns `server/`.
- Person 3 owns `dashboard/`.
- Person 4 owns `tests/` and `demo/`.

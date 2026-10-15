# MediShield contract

MediShield is a synthetic hackathon prototype. The contract below defines the
data shape and security checks shared by the gateway, backend, MCP wrapper, and
dashboard.

## Protected action

`ProtectedAction` has exactly these fields and rejects extras:

`patient_id`, `medication_id`, `dose`, `units`, `route`, `frequency`,
`duration`, and `order_id`.

`dose` is a string. Canonicalization trims and normalizes it as a finite,
positive decimal, rejects values over `1,000,000`, rejects input longer than
64 characters, and rejects a canonical representation longer than 128
characters. `5`, `5.0`, and `5.00` therefore have the same canonical dose.
Supported unit spellings are explicit: `mg`, `milligram`, and `milligrams`
canonicalize to `mg`, while `synthetic-units` remains `synthetic-units`. Other
units are rejected. Other required text fields must be non-empty, and unknown
action fields are rejected.

Canonical JSON is UTF-8, sorted by key, compact (`(',', ':')` separators), and
does not allow non-finite JSON values. Persisted approval JSON is parsed with
duplicate-key rejection and must already equal the canonical representation.

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
- `patients(patient_id, name_synthetic, org_id)`
- `approvals(approval_id, action_hash, action_json, approver_id, created_at, expires_at, revoked, consumed, approval_mac)`
- `orders(order_id, patient_id, medication_id, dose, units, route, frequency, duration)`
- `audit_events(id, time, request_id, actor_id, tool, action_type, approval_id, decision, risk, rule, reason, changed_fields, state_changed)`
- `tool_baseline(tool_name, fingerprint, allowed_destination)`
- `organizations(org_id, name, created_at)`
- `memberships(org_id, actor_id, role, active)`
- `documents(document_id, org_id, owner_actor_id, encrypted paths, content digests, processing/review status, sanitized detection report, deletion lifecycle fields, and signed receipt fields)`

The default database is `medishield.sqlite3` at the repository root. Tests may
inject a temporary path or an open SQLite connection.

`approval_mac` is an HMAC-SHA-256 authentication tag computed by the trusted
backend over the approval ID, canonical action, action fingerprint, clinician
ID, creation time, expiry time, policy tool, exact destination, and a schema
version. Its key is loaded only
from `MEDISHIELD_APPROVAL_SECRET` and must be at least 32 UTF-8 bytes. The
gateway uses `hmac.compare_digest`; it never accepts an agent-supplied hash or
MAC as proof. Rows without a valid tag fail closed.

Backend approval creation, revocation, order-state reads, and patient-record
reads require a server-resolved `WorkspaceUser` context. The backend
re-reads that actor's active membership and role from SQLite; a caller-supplied
role, organization, or Boolean authorization value is not accepted as proof.
Patient and approval operations are additionally checked against the stored
patient organization. Calls without this context fail closed.

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
3. Validate the actor's role and active membership in the patient's organization.
4. Pin the policy tool, the SQLite tool baseline, its fingerprint, and its exact destination.
5. Validate the approval's canonical action, stored content fingerprint, and gateway authentication tag.
6. Validate the approval exists, has valid UTC timestamps, is unexpired, is not revoked, is not consumed, was issued by a clinician, and is scoped to the patient's organization.
7. Recompute the protected-action hash and compare it with the authenticated approval hash.
8. Atomically consume the approval, write the order through `apply_order`, and write the audit event.
9. Audit every outcome that can be persisted safely.
10. Fail closed whenever a check, backend write, or audit write cannot be completed safely.

The MCP tool `execute_approved_order` always uses the policy name
`update_order` and delegates to `verify_execution`; it does not write the
`orders` table directly.

Registry drift blocks before approval consumption or order mutation. The block
reason carries compact sentinel context so the forensic reader can report the
expected and observed fingerprints without copying patient or action data.

The patient-record and security-event MCP tools also require a server-created
trusted local-demo context. An agent-supplied actor or organization string is
not sufficient. Patient scope is checked against the patient's stored
organization, and security-event reads are restricted to audit/admin roles.
The local context adapter is synthetic and must be replaced by authenticated
transport context before any real deployment.

Normal dispatcher calls inspect the live FastMCP registry through the Trust
Sentinel. An explicit registry override is permitted only by the isolated
synthetic tampering demonstration; it is not a normal-operation way to declare
an untrusted registry trusted.

Before `get_patient_record` releases data to the MCP caller, its response is
validated as the expected structured patient/order shape, checked against the
requested patient and authenticated organization, bounded to 256 orders and
64 KiB of compact UTF-8 JSON, and reduced to synthetic patient fields. Unknown
or malformed output is blocked and audited. This response guard validates the
declared structured response; it does not establish the safety of an arbitrary
Python callable, dependency, or remote MCP server.

Approval creation and revocation also create low-risk lifecycle audit events.
Those lifecycle operations are available only after a server-resolved clinician
context has been revalidated by the backend; passing `clinician_1` as a string
alone is insufficient.
The audit hash-chain verifier detects inconsistencies across the mutable SQLite
and JSONL stores, but it is not append-only storage and cannot stop an operator
with write access from rewriting every record and recomputing the chain.

## Synthetic document privacy contract

Document operations use a server-resolved active membership, never a trusted
client organization or role. `org_admin`, `clinician`, and `privacy_officer`
may upload; `org_admin` and `privacy_officer` may approve or reject privacy
review; researchers may retrieve only approved de-identified derivatives;
clinicians/privacy officers/org admins may retrieve approved originals; and
read-only auditors receive metadata/integrity status only. Unknown roles and
missing memberships fail closed.

The upload boundary accepts only UTF-8 TXT, PDF, PNG, and JPEG signatures up to
10 MiB. Stored original and derivative files are AES-256-GCM envelopes with a
fresh nonce and associated document/tenant/variant metadata. The master key
comes from `MEDISHIELD_DOCUMENT_KEY`; the separate pseudonym key comes from
`MEDISHIELD_PSEUDONYM_SECRET`. There is no fallback key. Original and
derivative SHA-256 digests are checked before plaintext is returned. A failed
authentication or digest check returns no content and records a sanitized
blocked audit event.

Text detection is deterministic and rule-based. Results are always marked for
human review and the report records categories/counts only, not matched
values. Image OCR is not configured in this MVP, so images remain manual
review items without a de-identified derivative. Missing malware scanning is
reported as `not_configured` and is never represented as a clean scan.

The local identity selector is development-only authentication. This MVP does
not claim a real identity provider, complete de-identification, clinical
correctness, regulatory compliance, or MCP exposure of document operations.

Privacy receipts are signed with a separate Ed25519 key pair loaded from
`MEDISHIELD_RECEIPT_SIGNING_PRIVATE_KEY` and
`MEDISHIELD_RECEIPT_SIGNING_PUBLIC_KEY`. Audit checkpoints use a different
pair loaded from `MEDISHIELD_AUDIT_CHECKPOINT_PRIVATE_KEY` and
`MEDISHIELD_AUDIT_CHECKPOINT_PUBLIC_KEY`. Missing or malformed key material
fails closed. Ordinary SHA-256 digests remain fingerprints and are not approval
authentication.

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
from server.db import initialize_db
from server.mcp_server import get_patient_record, execute_approved_order, trusted_execution_context

connection = initialize_db()

# Protected patient retrieval (fails closed with PermissionError on drift):
try:
    with trusted_execution_context(connection, "clinician_1", "ORG-DEMO"):
        patient_data = get_patient_record(patient_id="P-104")
except PermissionError as exc:
    # Denied before database record was accessed
    pass

# Protected order execution:
with trusted_execution_context(connection, "agent_1", "ORG-DEMO"):
    decision = execute_approved_order(
        request_id="REQ-001",
        actor_id="agent_1",
        approval_id="APR-001",
        action=action,
    )
connection.close()
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

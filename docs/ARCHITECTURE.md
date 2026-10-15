# MediShield architecture and security notes

## Zero-trust trust zones

MediShield treats the agent, prompt context, and tool arguments as an
untrusted zone; MCP is the protocol boundary; the gateway is the authoritative
reference monitor; and SQLite plus the dual audit stores are the authoritative
synthetic backend. A protected call therefore follows the same eight-stage
sequence on every path: strict request validation, server-resolved actor role,
tool/destination and registry checks, approval state and expiry, canonical
intent and authentication-tag verification, atomic single-use consumption and
backend mutation, audit persistence, and commit. Any failed stage rolls back
protected state and records a blocked outcome. This is the conceptual
zero-trust model used by the judge-facing protocol and threat-model documents.

## Components

1. The MCP wrapper accepts structured synthetic tool calls.
2. `server/backend.py` creates and revokes clinician approvals and exposes the
   synthetic order state.
3. `guard/gateway.py` is the only protected execution decision point.
4. `guard/sentinel.py` reads the actual FastMCP ToolManager registry and
   compares it with the explicit reviewed registry baseline.
5. `guard/forensics.py` derives concise read-only incident evidence from the
   existing audit row.
6. `server/backend.apply_order()` is the only function that writes the
   `orders` table and requires the gateway's caller-owned transaction.
7. `guard/audit.py` writes the contract event to SQLite and appends the same
   JSON object to `logs/events.jsonl`.
8. `guard/checkpoints.py` can sign the current audit-ledger head with a
   separate Ed25519 checkpoint key.
9. The Streamlit dashboard reads the shared repository-root database and calls
   the same gateway/demo functions used by the tests.
10. `privacy/deid.py`, `privacy/crypto.py`, `privacy/receipts.py`, and
   `privacy/vault.py` provide the
   tenant-scoped synthetic document workflow without bypassing the clinical
   gateway.

The protected flows are:

- **Approved Execution**: `propose action` → `clinician approval record + gateway authentication tag` → `MCP execution request` → `registry trust sentinel` → `gateway authorization and pinning` → `authenticated approval and action-hash comparison` → `single-use consume + order update + audit`.
- **Patient Record Retrieval**: authenticated local-demo context → `registry trust sentinel` → organization/role check → (if trusted) `query patient demographics & orders` / (if drifted or unauthorized) `audit blocked attempt + fail closed (PermissionError)` without invoking the protected handler.

- **Patient Response Release**: after the protected read, the MCP wrapper
  validates the response shape, requested patient and tenant scope, order
  fields, item count, and encoded size. It removes internal organization
  metadata before release. Invalid or oversized output is blocked and audited;
  an audit failure also fails closed. This is structured response validation,
  not proof that an arbitrary tool callable or remote server is trustworthy.

- **Document Privacy**: local-demo membership lookup → local file signature and
  size validation → rule-based PHI detection → encrypted original and
  derivative storage → privacy-officer review → tenant- and role-checked
  retrieval → AES-GCM authentication and SHA-256 verification → sanitized
  audit event. No uploaded content is sent to an external service.

The document flow uses additive SQLite tables (`organizations`,
`memberships`, and `documents`). Encrypted files are kept outside public
directories under `.medishield_vault/`; file names are generated document
identifiers rather than upload names. A missing key, failed decryption,
content digest mismatch, unknown membership, unsupported file, or missing
privacy review blocks the operation.

Each accepted upload or review also receives a signed, non-content privacy
receipt containing encrypted-artifact digests, pipeline version, review state,
and its audit-event reference. Receipt signing uses a dedicated Ed25519 key
pair and does not establish that de-identification is complete. Document
deletion is a recoverable pending/failed/deleted state transition with a
retained metadata tombstone and an explicit reconciliation operation.

## Trust Sentinel

The FastMCP `ToolManager.list_tools()` listing is read without running any tool.
Each declaration is reduced to stable JSON containing the tool name, input
schema, output schema, and declared interface metadata. The explicit expected registry is
stored in source and is reviewed like security policy. A changed schema,
description, metadata, added tool, missing tool, or inspection error returns a
non-eligible result. Both execution requests and patient-record retrievals
enforce this gate, recording a blocked audit event and failing closed before
sensitive data or state is touched.

The status helper `server.mcp_server.get_tool_integrity_status()` is read-only
and is intended for direct tests and demonstrations. Dedicated demo helpers
`server.mcp_server.tamper_runtime_registry()` and `restore_runtime_registry()`
allow non-destructive live demonstration and verification. They are not extra
MCP tools, so the public MCP surface remains the existing five tools.
The normal `dispatch_mcp_tool_call()` path also consults the live FastMCP
registry. Its optional registry override is reserved for the isolated synthetic
tampering demonstration and is not a normal-operation trust source.

## Forensic evidence & Audit Trail Integrity

`guard/forensics.evidence_for_request()` reads the newest matching audit row
and returns an incident ID, timestamp, request, actor, tool, failed check,
decision, state-change flag, audit reference, detected differences, and sentinel
fingerprints when available. It distinguishes simulated attack evidence
(`evidence_type="simulated_attack"`, `is_simulation=True`) from production
events. It deliberately excludes patient IDs, medication IDs, doses, and
the full action JSON.

The audit trail is protected by a cryptographic SHA-256 hash chain and
cross-store verification (`guard.forensics.verify_audit_integrity`):
- **Modification detection**: Canonical event JSON is hashed into the sequential chain; any field modification changes the chain digest or triggers a cross-store mismatch between JSONL and SQLite.
- **Deletion detection**: Checked via sequential SQLite `audit_events.id` continuity and cross-store record count reconciliation.
- **Reordering detection**: Checked via strict UTC timestamp monotonicity and sequence ID ordering.
- Timestamps are real UTC values; no immutable guarantees are falsely claimed for mutable operating system files.

Signed checkpoints add an independently verifiable signature over the current
SQLite ledger head. They detect a changed ledger when the checkpoint and public
key are available, but they do not make the checkpoint file append-only.

## Clinical Intent Lock

The approval stores canonical action JSON and a SHA-256 digest calculated by
the server. It also stores an HMAC-SHA-256 tag created from a gateway-only
secret and the complete approval envelope: approval ID, action, action digest,
clinician ID, creation time, expiry time, and schema version. At execution, the
gateway validates the structured action, validates the persisted canonical JSON,
recomputes the tag and digest, and compares both with the stored values. The
agent cannot provide a replacement digest or tag to make a changed action
valid. Missing or invalid secret configuration fails closed.

The check covers the patient, medication, dose, units, route, frequency,
duration, and order ID. Decimal dose normalization makes equivalent decimal
spellings compare consistently while rejecting malformed, non-finite, zero,
negative, oversized, or overly long input.

## Transaction boundary

When it owns the transaction boundary, the gateway begins an immediate SQLite
transaction before protected checks that need database state. A successful path
consumes the approval, calls `apply_order`, writes the audit event, and commits.
When a caller supplies an already-active transaction, the gateway uses a
savepoint and does not commit the caller's work. A backend or audit failure
rolls back the protected unit and returns a blocked decision. The JSONL append
is not a SQLite transaction; a filesystem failure is propagated and the gateway
does not report success.

## Trust boundaries

- Agent input is untrusted, including actor claims, action fields, approval IDs,
  and destination strings.
- The approval row and actor directory are server-side SQLite state.
- The policy module and the required `tool_baseline` row provide the synthetic
  tool/destination baseline.
- The dashboard is a demonstration client, not an authority.
- The local trusted execution context is only an adapter for this synthetic
  demo; it is not a replacement for a real authenticated session.

The prototype checks the exact registered fingerprint and destination for
`update_order`. This is a focused demonstration control and does not promise
to detect every tool-description, implementation, remote-server, or
supply-chain attack. The sentinel fingerprints declared interfaces only; it
does not hash or verify the Python callable, source, bytecode, dependencies, or
remote implementation behind a tool. A source baseline update is a manual maintenance change;
the runtime never accepts a new registry merely because it was observed.

The privacy service is currently available through the dashboard and direct
backend service APIs, not as new MCP tools. This is a deliberate safe MVP
boundary: the existing five-tool registry remains unchanged and its reviewed
sentinel baseline remains valid. A future MCP document surface must add
narrowly scoped tools and a reviewed registry baseline before exposure.

The backend compatibility helper and `apply_order` require a private gateway
capability; calling either directly without that capability does not create a
second protected execution path. Patient-record, order-state, approval
creation, and approval-revocation helpers also require a server-resolved
`WorkspaceUser` and re-read active membership and role from SQLite. The
patient organization is checked before a record or order state is returned.
The guard-off demo is the sole deliberate execution exception, and it passes
the internal capability only inside a temporary synthetic fixture marked as
intentionally vulnerable. The local context remains a demo adapter, not real
user authentication.

The Trust Sentinel fingerprints declared MCP interfaces, including output
schemas, but does not verify the Python callable, source, bytecode,
dependencies, or remote server behind a matching declaration.

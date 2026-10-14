# MediShield architecture and security notes

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
8. The Streamlit dashboard reads the shared repository-root database and calls
   the same gateway/demo functions used by the tests.

The protected flows are:

- **Approved Execution**: `propose action` → `clinician approval record` → `MCP execution request` → `registry trust sentinel` → `gateway authorization and pinning` → `hash comparison` → `single-use consume + order update + audit`.
- **Patient Record Retrieval**: `get_patient_record request` → `registry trust sentinel` → `gateway verification` → (if trusted) `query patient demographics & orders` / (if drifted) `audit blocked attempt + fail closed (PermissionError)` without accessing patient state.

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

## Clinical Intent Lock

The approval stores canonical action JSON and a SHA-256 digest calculated by
the server. At execution, the gateway validates the structured action,
canonicalizes it again, recomputes the digest, and compares it with the stored
approval. The agent cannot provide a replacement digest to make a changed
action valid.

The check covers the patient, medication, dose, units, route, frequency,
duration, and order ID. Decimal dose normalization makes equivalent decimal
spellings compare consistently while rejecting malformed, non-finite, zero,
negative, oversized, or overly long input.

## Transaction boundary

The gateway begins an immediate SQLite transaction before protected checks that
need database state. A successful path consumes the approval, calls
`apply_order`, writes the audit event, and commits. A backend or audit failure
rolls back the order and approval and returns a blocked decision. The JSONL
append is not a SQLite transaction; a filesystem failure is propagated and the
gateway does not report success.

## Trust boundaries

- Agent input is untrusted, including actor claims, action fields, approval IDs,
  and destination strings.
- The approval row and actor directory are server-side SQLite state.
- The policy module and the required `tool_baseline` row provide the synthetic
  tool/destination baseline.
- The dashboard is a demonstration client, not an authority.

The prototype checks the exact registered fingerprint and destination for
`update_order`. This is a focused demonstration control and does not promise
to detect every tool-description, implementation, remote-server, or
supply-chain attack. The sentinel fingerprints declared interfaces only; it
does not hash or verify the Python callable, source, bytecode, dependencies, or
remote implementation behind a tool. A source baseline update is a manual maintenance change;
the runtime never accepts a new registry merely because it was observed.

The backend compatibility helper also requires a private gateway capability;
calling it directly does not create a second protected execution path. The
guard-off demo is the sole deliberate exception, and it calls `apply_order`
only inside a temporary synthetic fixture marked as intentionally vulnerable.

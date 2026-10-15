# MediShield — Runtime Security Gateway for MCP-Connected Clinical AI

> Hackathon prototype: a fail-closed runtime security boundary for synthetic
> healthcare workflows driven through the Model Context Protocol (MCP).

MediShield sits between an AI-agent-style caller and a simulated clinical
backend. It verifies that a proposed state-changing action is structurally
valid, authorized for the caller and tenant, bound to a trusted tool
declaration and destination, explicitly approved by a clinician, and still
valid at execution time. It is a security demonstration, not a clinical
product, medical advice, or a regulatory-compliance system.

All patients, orders, actors, documents, and audit events in this repository
are synthetic.

## What it solves

MCP standardizes tool declarations and invocation, but application-level
authorization for high-consequence operations remains the application’s
responsibility. An agent can be induced to alter a dose, substitute a
patient, replay an approval, invoke a tool with the wrong role, or operate
against a changed tool declaration.

MediShield addresses that execution-boundary problem with:

- Strict Pydantic contracts for protected actions and execution requests.
- Deterministic action canonicalization and SHA-256 content hashing.
- Gateway-controlled HMAC authentication for approval records.
- Clinician-scoped, tenant-scoped, time-limited, revocable, single-use
  approvals.
- Explicit role, organization-membership, tool-baseline, and destination
  checks.
- MCP Trust Sentinel verification before protected handlers are reached.
- Atomic approval consumption, backend mutation, and audit recording.
- Tenant-scoped encrypted document processing and privacy review.
- Read-only forensic evidence and optional signed audit checkpoints.

## B2B healthcare use case

The intended B2B scenario is a healthcare organization using an AI agent to
assist with clinical workflows while retaining human authorization over
high-consequence changes:

1. A clinician approves one structured synthetic medication action.
2. An AI client submits the approved action through the MCP boundary.
3. MediShield verifies the authenticated local-demo identity, tenant scope,
   tool registry, destination, approval status, and action fingerprint.
4. Only an exact, active approval can reach the simulated order writer.
5. Every allowed or blocked outcome is recorded for security operations review.

The dashboard also demonstrates patient-directory access, privacy-reviewed
documents, Trust Sentinel drift detection, and audit/forensic inspection.
The local identity selector is a seeded demo adapter, not an enterprise
identity provider.

## Implemented components

### MCP boundary — server/mcp_server.py

The current FastMCP server declares these five tools:

| MCP tool | Implemented behavior |
| --- | --- |
| get_patient_record | Retrieves one synthetic patient and that patient’s synthetic orders after Trust Sentinel verification, authenticated local-demo context, organization/role authorization, and response validation. |
| propose_medication_order | Validates a ProtectedAction and returns a proposal without changing state. |
| request_clinician_approval | Creates a time-limited approval from a server-authenticated clinician context. |
| execute_approved_order | Builds an ExecutionRequest and delegates protected order execution to guard.gateway.verify_execution. It does not call the backend directly. |
| get_security_events | Returns audit events visible to the authenticated audit or administrative role within the organization scope. |

~~~powershell
python -m server.mcp_server
~~~

The policy vocabulary in guard/policy.py also contains entries such as
cancel_order and dispense_simulated, but this checkout does not expose those
names as FastMCP handlers. The active MCP surface is the five tools listed
above.

### Security guard and approval workflow

- guard/models.py defines strict Pydantic contracts with extra fields rejected.
- guard/intent.py validates and canonicalizes patient, medication, dose, units,
  route, frequency, duration, and order. Doses are finite positive decimal
  strings with demo sanity limits; supported unit aliases are explicit.
- guard/approval.py authenticates the complete persisted approval record with
  HMAC-SHA-256 using MEDISHIELD_APPROVAL_SECRET. The action hash is a content
  fingerprint; it is not approval authenticity by itself.
- server/backend.py creates and revokes approvals only through an authenticated
  clinician context. Approval rows include the canonical action, action hash,
  timestamps, revocation/consumption state, and authentication tag.
- guard/policy.py contains role permissions and pinned destinations.
- guard/gateway.py is the authoritative protected execution path. It validates
  the request, checks registry trust, resolves actor role and patient
  organization, checks the database tool baseline and destination, authenticates
  and validates the approval, enforces expiry/revocation/single-use state,
  compares the recomputed action hash, and invokes the backend only after all
  checks pass.
- server/backend.apply_order() is the sole order-table writer and requires a
  private gateway capability. The gateway uses a transaction or savepoint so
  approval consumption, order update, and audit outcome can roll back together.

### MCP Trust Sentinel — guard/sentinel.py

The Sentinel stores an explicit reviewed registry in source control; it never
learns a trusted baseline from the observed runtime registry. It canonicalizes
and fingerprints tool names, descriptions, input/output schemas, and interface
metadata, then compares the live FastMCP registry with that baseline.

The protected path fails closed on missing or unexpected tools, tool renaming,
input or output schema drift, interface metadata drift, registry inspection
failure, and invalid or missing trusted baseline data.

demo/attacks.py and the MCP Trust Sentinel dashboard page demonstrate
tampering, handler non-invocation, restoration, and authorized resumption.

### Patient directory and EHR demonstration

dashboard/patient_view.py provides the Patient Directory & EHR page.
server/backend.py reads synthetic patients and orders only through an
authenticated local-demo organization context. The MCP patient path validates
response shape, patient identifier, tenant scope, order fields, item count,
and serialized response size before releasing a minimized response. Invalid
or oversized responses are blocked and audited.

This is a simulated SQLite backend, not an EHR or FHIR integration.

### Secure document vault and privacy workflow

privacy/vault.py and dashboard/document_vault.py implement a tenant-scoped
local workflow:

1. Validate filename, extension, file signature, UTF-8 content where
   applicable, and a 10 MiB demo size limit.
2. Extract text from TXT and text-based PDF files using local code.
3. Detect rule-based PHI-like identifiers with privacy/deid.py.
4. Generate a redacted or organization-scoped pseudonymized derivative, or
   keep detection-only mode without creating a retrievable derivative.
5. Encrypt originals and derivatives with AES-256-GCM using
   MEDISHIELD_DOCUMENT_KEY.
6. Require explicit privacy-officer review before retrieval.
7. Enforce organization and role permissions for metadata, derivative
   retrieval, original retrieval, and deletion.
8. Verify decrypted content against stored SHA-256 digests.
9. Store a signed, non-content privacy receipt when receipt-signing keys are
   configured.
10. Support recoverable deletion states with metadata tombstones and
    reconciliation.

Supported uploads are TXT, PDF, PNG, and JPEG. Local OCR is not configured,
so image uploads remain manual-review items. PDF extraction may require manual
review when no text is available or the PDF is encrypted.

### Audit and forensic evidence

guard/audit.py records structured decisions in SQLite table audit_events and
the append-only JSONL file logs/events.jsonl.

guard.audit.verify_audit_log_integrity() checks event normalization, sequence
continuity, timestamp ordering, hash-chain consistency, and SQLite/JSONL parity
where both stores are available. This is tamper evidence, not immutable or
WORM storage.

guard/forensics.py provides read-only evidence records without copying
protected action contents into the evidence record. guard/checkpoints.py can
sign the current audit-ledger head with a separate Ed25519 key pair. The
checkpoint file itself remains ordinary mutable filesystem storage.

### Streamlit dashboard

dashboard/app.py is the Streamlit entry point. It currently provides:

- Overview
- Patient Directory & EHR
- Clinician Approval Hub
- Intent Lock Verification
- MCP Trust Sentinel
- Secure Document Vault
- Security Test Lab
- Audit Log & Forensic Ledger

Reusable visual components are in dashboard/theme.py. Feature views are in
dashboard/patient_view.py, dashboard/approval_view.py,
dashboard/sentinel_view.py, dashboard/document_vault.py, and
dashboard/forensics_view.py.

## Architecture

~~~mermaid
flowchart LR
    A[AI agent or MCP client] -->|stdio JSON-RPC| M[FastMCP server]
    M --> S[Trust Sentinel]
    S -->|trusted registry| G[Security gateway]
    G --> P[Role, tenant, destination and approval checks]
    P --> I[Canonical intent and HMAC verification]
    I --> T[Atomic transaction]
    T --> B[SQLite synthetic backend]
    T --> L[SQLite audit_events plus logs/events.jsonl]
    S -->|drift or unverifiable| X[Blocked and audited]
    G -->|failure| X
~~~

### Protected order workflow

1. propose_medication_order validates the structured action without writing.
2. A server-authenticated clinician calls request_clinician_approval.
3. server/backend.py canonicalizes the action, computes its SHA-256 hash,
   creates timestamps, and authenticates the approval with the gateway HMAC.
4. The caller submits execute_approved_order.
5. The MCP boundary verifies trusted context and constructs an
   ExecutionRequest for the internal policy tool update_order.
6. The gateway checks the live registry, tenant and role, pinned destination,
   database baseline, approval authenticity, timestamps, revocation, expiry,
   consumption state, and recomputed action hash.
7. On an exact match, SQLite marks the approval consumed, writes the order,
   records the audit event, and commits.
8. On failure, protected state is not committed and a blocked decision is
   recorded where the audit store is available.

### Patient-record workflow

A trusted local-demo context is resolved from SQLite. The Sentinel verifies
the declared MCP registry before the backend handler is reached. The user
must have patient_read permission and active membership in the patient’s
organization. The response is validated and minimized before release.
Registry drift, missing context, tenant mismatch, response-shape drift,
handler failure, or audit failure causes a denial.

### Document workflow

The vault uses organization-scoped SQLite metadata and encrypted files below
.medishield_vault/. It does not send uploaded content to an external service.
Uploads remain pending until privacy review; retrieval requires the appropriate
organization membership and role.

## Repository structure

~~~text
Medishield/
├── .streamlit/config.toml       # Streamlit theme and server settings
├── AGENTS.md                    # Contributor rules and security invariants
├── README.md                    # This overview and operating guide
├── requirements.txt             # Runtime and test dependencies
├── pytest.ini                   # Pytest discovery and repository import path
├── dashboard/                   # Streamlit operations console
│   ├── app.py                   # Entry point and navigation
│   ├── theme.py                 # Shared UI components and theme helpers
│   ├── patient_view.py          # Patient directory/EHR view
│   ├── approval_view.py         # Approval creation, revocation and execution
│   ├── sentinel_view.py        # Trust Sentinel and tampering demonstration
│   ├── document_vault.py        # Privacy vault UI
│   ├── forensics_view.py        # Audit and checkpoint UI
│   ├── security_helpers.py      # Dashboard fixtures and gateway adapters
│   └── dosage.py                # Audit-event dosage comparison helpers
├── guard/                       # Security enforcement and evidence
│   ├── approval.py              # Approval authentication
│   ├── audit.py                 # Dual-store audit persistence and integrity
│   ├── checkpoints.py           # Signed audit checkpoints
│   ├── forensics.py             # Read-only evidence retrieval
│   ├── gateway.py               # Authoritative execution verification
│   ├── intent.py                # Canonical action and SHA-256 hashing
│   ├── models.py                # Strict Pydantic contracts
│   ├── policy.py                # Role and destination policy
│   └── sentinel.py              # MCP registry trust verification
├── server/                      # FastMCP boundary and synthetic backend
│   ├── mcp_server.py            # Five current MCP tool handlers
│   ├── backend.py               # Approvals, patients and order writes
│   └── db.py                    # SQLite schema, migration and seed data
├── privacy/                     # Tenant authorization and document privacy
│   ├── auth.py                  # Local-demo organization membership
│   ├── crypto.py                # AES-GCM, pseudonym and digest primitives
│   ├── deid.py                  # Rule-based identifier detection
│   ├── receipts.py              # Ed25519 privacy receipts
│   └── vault.py                 # Encrypted document lifecycle
├── demo/                        # Isolated synthetic demonstrations
│   ├── attacks.py               # Attack, control and vault workflows
│   └── seed_synthetic_events.py # Synthetic audit-event fixture generator
├── logs/
│   └── sample_events.jsonl      # Checked-in synthetic sample events
├── docs/                        # Detailed architecture and demo notes
└── tests/                       # Pytest suite for gateway, MCP, privacy and UI helpers
~~~

Runtime-generated files include the repository-root medishield.sqlite3,
logs/events.jsonl, .medishield_vault/, and optionally
logs/audit_checkpoints.jsonl. The database, runtime event log, vault, Python
cache, and virtual environment are excluded by .gitignore where applicable.

## Windows PowerShell setup

### Prerequisites

- Windows 10 or 11.
- PowerShell 5.1+ or PowerShell 7+.
- Python 3.11 or newer.
- Node.js and npx only if you want to use MCP Inspector.

All commands below run from the repository root.

### Install

~~~powershell
cd C:/path/to/Medishield
py -3.11 -m venv .venv
./.venv/Scripts/Activate.ps1
python -m pip install -r requirements.txt
~~~

If PowerShell blocks activation for the current process:

~~~powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
./.venv/Scripts/Activate.ps1
~~~

### Environment variables

Approval creation and protected order execution require at least 32 UTF-8
bytes in MEDISHIELD_APPROVAL_SECRET:

~~~powershell
$env:MEDISHIELD_APPROVAL_SECRET = (python -c "import secrets; print(secrets.token_hex(32))")
~~~

The secure document workflow requires a separate 32-byte key in
MEDISHIELD_DOCUMENT_KEY:

~~~powershell
$env:MEDISHIELD_DOCUMENT_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
~~~

Pseudonymization additionally requires the separate
MEDISHIELD_PSEUDONYM_SECRET:

~~~powershell
$env:MEDISHIELD_PSEUDONYM_SECRET = (python -c "import secrets; print(secrets.token_hex(32))")
~~~

Keep these values in the current PowerShell session, do not commit or print
them, and keep the approval secret unchanged between approval creation and
execution. Missing or malformed values fail closed. The receipt and
checkpoint key pairs below are required for those workflows:

- MEDISHIELD_RECEIPT_SIGNING_PRIVATE_KEY
- MEDISHIELD_RECEIPT_SIGNING_PUBLIC_KEY
- MEDISHIELD_RECEIPT_SIGNING_KEY_ID
- MEDISHIELD_AUDIT_CHECKPOINT_PRIVATE_KEY
- MEDISHIELD_AUDIT_CHECKPOINT_PUBLIC_KEY
- MEDISHIELD_AUDIT_CHECKPOINT_KEY_ID

Use the key-generation procedure in docs/README.md or docs/DEMO_SCRIPT.md
for Ed25519 pairs. Receipt keys are required for document upload/review;
checkpoint keys are needed only when creating or verifying checkpoints.

## Run the project

### Test suite

~~~powershell
python -m pytest -q
~~~

pytest.ini discovers tests from tests/ and adds the repository to the import
path. Coverage includes the gateway, canonicalization, approvals, rollback,
audit integrity, MCP registry and patient authorization, dashboard security
helpers, synthetic data, privacy vault, signed receipts, checkpoints, and
forensic retrieval.

Useful focused commands:

~~~powershell
python -m pytest -q tests/test_gateway_security.py tests/test_security_foundation.py
python -m pytest -q tests/test_mcp_server.py tests/test_sentinel.py tests/test_sentinel_tampering.py
python -m pytest -q tests/test_privacy_workflow.py tests/test_evidence.py
~~~

This README does not embed a stale pass count. During this update, the managed
Codex environment could not complete collection with the repository local
virtual-environment executable: it was inaccessible, and the fallback Python
runtime stopped at collection because available Windows MCP dependencies
included incompatible or missing binary modules, including pywintypes and rpds.
No passing full-suite result is claimed from that environment. Run the command
in a clean activated virtual environment after installing requirements.txt.

### Streamlit dashboard

~~~powershell
python -m streamlit run dashboard/app.py
~~~

The app uses the repository-root SQLite database. Open
http://localhost:8501 if the browser does not open automatically.

### MCP server and Inspector

~~~powershell
python -m server.mcp_server
npx -y @modelcontextprotocol/inspector --cli python -m server.mcp_server --method tools/list
~~~

The server is a FastMCP stdio process, not a normal browser API or HTTP
server. The Inspector requires Node.js and npx.

### Synthetic command-line demonstrations

These helpers create temporary databases and do not modify the repository
database:

~~~powershell
python -c "from pprint import pprint; from demo.attacks import valid_action; pprint(valid_action())"
python -c "from pprint import pprint; from demo.attacks import tamper_dose; pprint(tamper_dose())"
python -c "from pprint import pprint; from demo.attacks import substitute_patient; pprint(substitute_patient())"
python -c "from pprint import pprint; from demo.attacks import replay_consumed_approval; pprint(replay_consumed_approval())"
python -c "from pprint import pprint; from demo.attacks import tool_registry_tampering; pprint(tool_registry_tampering())"
python -c "from pprint import pprint; from demo.attacks import document_vault_workflow; pprint(document_vault_workflow())"
~~~

valid_action() is the exact-match control. Tampering, replay, and registry
drift demonstrations should return blocked decisions. These are demonstration
outputs; automated assertions are in tests/ and must be run separately.
guard_off_vs_guard_on() intentionally calls the private simulated backend
capability inside an isolated fixture to show an unguarded write versus a
guarded rejection. It is not a production execution path.

## Demonstrating the dashboard

1. Configure MEDISHIELD_APPROVAL_SECRET and launch the Streamlit command.
2. Select the synthetic organization and demo actor in the sidebar.
3. Use Clinician Approval Hub to inspect, create, revoke, and execute
   approvals. Backend authorization still applies; the UI does not grant it.
4. Use Security Test Lab to run eight synthetic scenarios plus the exact-match
   control. Review the actual decision, rule, changed fields, and state
   comparison.
5. Use MCP Trust Sentinel to run registry-tampering and confirm the protected
   handler is not invoked while drift is present.
6. Use Patient Directory & EHR to inspect tenant-scoped synthetic records.
7. Configure document and receipt keys before using Secure Document Vault.
   Upload a synthetic TXT/PDF/PNG/JPEG document, review the report, approve it
   with the seeded privacy-officer identity, verify integrity, and retrieve a
   role-permitted variant.
8. Use Audit Log & Forensic Ledger to inspect events, run the hash-chain
   check, and create or verify a signed checkpoint when keys are configured.

A blocked dashboard decision demonstrates a security rejection; it is not by
itself proof that an automated test assertion passed. Use the corresponding
pytest test for that claim.

## Security controls and source references

| Control | Source |
| --- | --- |
| Strict request and action contracts | guard/models.py, guard/gateway.py |
| Canonical JSON, decimal dose normalization and explicit units | guard/intent.py |
| Approval MAC and secret validation | guard/approval.py, server/backend.py |
| Role and destination policy | guard/policy.py, privacy/auth.py |
| Tenant-scoped patient access and response validation | server/mcp_server.py, server/backend.py |
| Registry name/schema/metadata fingerprinting | guard/sentinel.py |
| Single-use approval consumption and rollback | guard/gateway.py, server/backend.py |
| Structured dual-store audit persistence | guard/audit.py |
| Audit hash-chain and forensic evidence | guard/audit.py, guard/forensics.py |
| Signed audit checkpoints | guard/checkpoints.py |
| AES-256-GCM document storage and integrity checks | privacy/crypto.py, privacy/vault.py |
| Rule-based detection and pseudonymization | privacy/deid.py, privacy/crypto.py |
| Signed privacy receipts | privacy/receipts.py, privacy/vault.py |

## Known limitations and incomplete functionality

MediShield is a synthetic, single-repository demonstration. The following
are deliberately not claimed:

- No real EHR, FHIR, SMART-on-FHIR, pharmacy, or external healthcare
  integration.
- No production identity provider, network authentication, session management,
  external key-management service, or multi-process deployment protocol.
- The seeded local identity selector is not proof of a user’s real identity.
- Trust Sentinel verifies the declared tool interface. It does not prove that
  a remote server, implementation, dependency, endpoint, or runtime behavior
  is safe.
- The approval HMAC secret is application configuration, not a complete
  enterprise key-management system.
- SQLite and JSONL writes are not one atomic cross-filesystem transaction.
  The integrity verifier provides tamper evidence, not immutable storage.
- The document detector is local and rule-based. It is not a complete
  de-identification, malware-scanning, OCR, or compliance service.
- Image OCR is not configured and unsupported PDF conditions require manual
  review.
- The current MCP registry contains five implemented handlers. Adding policy
  names or new document tools requires a separately reviewed Sentinel baseline
  update, handler implementation, authorization tests, and documentation.
- docs/MCP_SPECIFICATION.md contains older target/reference material for tool
  names and a placeholder implementation description. For active runtime
  behavior, use server/mcp_server.py and guard/sentinel.py.

## Troubleshooting

- Approval authentication unavailable: set MEDISHIELD_APPROVAL_SECRET to at
  least 32 UTF-8 bytes and keep it stable between approval creation and
  execution.
- Approval expired, revoked, consumed, or invalid: create a new approval; old
  approvals are intentionally not repaired or silently reused.
- Gateway reports a degraded environment: the dashboard checks database schema,
  the action-hash self-test, and approval-secret configuration.
- Document key or receipt errors: configure the required 32-byte document key
  and Ed25519 receipt variables. Pseudonymization also needs its separate
  32-byte secret.
- Missing audit checkpoint key: checkpoint creation requires the private key
  and key ID; verification requires the corresponding public key and key ID.
- PowerShell activation fails: use Set-ExecutionPolicy -Scope Process
  -ExecutionPolicy Bypass for the current process, or use an activated
  environment.
- Stale local approvals: rows from databases created before approval MAC
  support are rejected by design. Create new approvals with the current secret
  rather than bypassing verification.
- MCP Inspector does not connect: verify Node.js/npx, the active virtual
  environment, and the repository-root working directory.

## Further documentation

- AGENTS.md — contributor rules and non-negotiable invariants.
- docs/README.md — extended setup, demos, privacy workspace, and verification.
- docs/ARCHITECTURE.md — component and trust-zone details.
- docs/CONTRACT.md — audit, approval, and privacy contracts.
- docs/MCP_DEMO.md — Windows demonstration walkthrough.
- docs/THREAT_MODEL.md — threat analysis and residual risk.
- docs/MCP_SPECIFICATION.md — reference material; verify active handlers
  against source as noted above.

## Synthetic-data notice

This repository contains only synthetic demonstration data. Do not upload
real patient information, credentials, production keys, or regulated data.

---

<<<<<<< HEAD
## 10. MCP Inspector & Client Connection Guide

### Current Server Status

The MCP server exposes the reviewed five-tool surface and applies the Trust
Sentinel, authenticated local-demo context, patient authorization, and gateway
checks before protected handlers run.

### Connecting to MCP Inspector (Target Integration)

Once the stdio tool bindings in `server/mcp_server.py` are active, developers can launch the official Anthropic MCP Inspector:

```powershell
npx @modelcontextprotocol/inspector .\.venv\Scripts\python.exe server/mcp_server.py
```

### Reference Client Configuration (`claude_desktop_config.json`)

To register MediShield with Claude Desktop or any compliant MCP host:

```json
{
  "mcpServers": {
    "medishield": {
      "command": "C:\\Users\\User\\Downloads\\Medishield-main\\Medishield-main\\.venv\\Scripts\\python.exe",
      "args": ["-m", "server.mcp_server"]
    }
  }
}
```

Detailed technical integration notes and tool schemas are documented in [docs/MCP_SPECIFICATION.md](docs/MCP_SPECIFICATION.md).

---

## 11. Threat Model & Mitigations

MediShield targets specific risks identified in the **OWASP Top 10 for LLMs** and **MCP Security Guidance**:

1. **LLM01: Prompt Injection / Tool Argument Manipulation:** An attacker injects instructions into clinical unstructured notes attempting to alter dosages.
   *Mitigation:* Unstructured notes are strictly excluded from the canonical intent lock schema. The gateway compares recomputed digests against the pre-approved baseline.
2. **LLM06: Excessive Agency / Confused Deputy:** An LLM client attempts to perform actions beyond its authorization.
   *Mitigation:* RBAC check (`is_role_permitted`) rejects unauthorized roles before intent verification begins.
3. **Approval Replay:** A compromised agent intercepts a valid approval ID and re-submits it.
   *Mitigation:* The database consumes the approval token atomically (`consumed = 1`) within the update transaction. Replays fail closed.
4. **Tool Destination Spoofing:** A rogue or contaminated tool definition attempts to post clinical records to an unauthorized URL.
   *Mitigation:* Baseline destination registry pins tool destinations to trusted internal URIs (`backend://simulated-ehr/*`).

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for full STRIDE analysis.

---

## 12. Synthetic privacy workspace

The local MVP also provides a tenant-scoped document vault. TXT and PDF text
can be processed with local rule-based PHI detection; PNG/JPEG files are stored
encrypted but remain manual-review items because OCR is not configured.
Originals and text derivatives use AES-256-GCM, and stored content is
SHA-256-verified before retrieval. The service requires
`MEDISHIELD_DOCUMENT_KEY`; pseudonymization additionally requires the separate
`MEDISHIELD_PSEUDONYM_SECRET`. There is no fallback key.

The dashboard's document workflow uses a local synthetic identity selector,
server-side organization and role checks, signed non-content receipts, and
explicit review gates. These are demonstration controls, not a production
identity provider, complete de-identification, immutable storage, or a
regulatory-compliance claim. Document operations intentionally remain outside
the five-tool MCP registry until a separately reviewed registry update.

## 13. Limitations & Production Roadmap

MediShield is an educational and architectural proof-of-concept. For full production readiness, the following roadmap items are planned:

- **Asymmetric Cryptographic Signatures:** Upgrading approvals from SHA-256 database tokens to Ed25519 public-key signatures issued via clinical smart cards or hardware tokens.
- **Distributed Nonce & Replay Cache:** Replacing local SQLite atomic locking with a distributed Redis/etcd consensus cache for high-throughput multi-node deployments.
- **Enterprise EHR Adapters:** Integrating standard FHIR R4 / SMART-on-FHIR REST endpoints in place of the simulated SQLite backend.
- **Cryptographic Audit Chaining:** Implementing Merkle tree verification or tamper-evident transparency logs for audit events.

---

## 14. Standards & References

- [Model Context Protocol (MCP) Specification](https://spec.modelcontextprotocol.io/)
- [Anthropic MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [OWASP Top 10 for Large Language Model Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [IETF RFC 8785: JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)

---

## 15. AI Use & Compliance Disclosure

In strict accordance with the hackathon rules and project conventions ([AGENTS.md](AGENTS.md)):
- **Handcrafted Security Logic:** The two core security functions—canonicalization & hash computation (`guard/intent.py`) and execution verification (`guard/gateway.py`)—were authored by hand.
- **AI Assistance:** AI coding tools were used strictly for scaffolding, documentation drafting, test fixtures, and dashboard presentation.
- **Synthetic Data Notice:** All patient names, medication identifiers, dosages, orders, and clinical records are entirely synthetic.

---

*MediShield — Securing the boundary where autonomous AI meets high-stakes action execution.*


## 16. Team Name

BREACH PLEASE 

---

## 17. Team Member Names

i. Sambhav Barua
2. Satyam Agarwalla
3. Adithya M
4. Nipun Reddy








=======
_MediShield is a runtime security demonstration for the boundary where
autonomous AI meets high-stakes action execution._
>>>>>>> 146b3f3 (Update MediShield README documentation)

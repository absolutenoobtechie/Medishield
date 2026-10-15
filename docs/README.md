# MediShield

MediShield is a HackUrity 2026 Track A demonstration of a runtime security
gateway between an AI-agent-style caller and a simulated clinical backend. All
patients, orders, actors, and events are synthetic. This is not medical advice,
not a clinical system, and not a regulatory-compliance claim.

The central control is the Clinical Intent Lock: a clinician approves one exact
structured action, and the gateway recomputes the action hash at execution time.
An altered dose, patient, medication, route, frequency, duration, or order ID
does not match the approval and is blocked. Approvals are also time-limited,
revocable, single-use, and authenticated with a gateway-controlled secret.
The SHA-256 action hash is a content fingerprint; the authentication tag is
what prevents a caller who knows the action from manufacturing an approval.

## Architecture

The project is intentionally small:

- `guard/` contains the strict models, action canonicalization and hashing,
  policy checks, Trust Sentinel, gateway transaction, audit persistence,
  signed audit checkpoints, and forensic evidence reader.
- `server/` contains the SQLite setup, synthetic backend, approval functions,
  and FastMCP wrapper.
- `dashboard/` contains the Streamlit demonstration UI.
- `demo/` contains isolated synthetic attack scenarios, including the clearly
  labeled guard-off versus guard-on comparison.
- `tests/` contains gateway, backend, audit, MCP, smoke, and attack tests.

The protected flow is:

`propose action` → `clinician approval record` → `MCP execution request` →
`Trust Sentinel registry check` → `gateway validation and pinning` → `hash
comparison and approval authentication` → `single-use consume + order update +
  audit` → `optional signed audit checkpoint`.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [CONTRACT.md](CONTRACT.md) for the
field-level contract and threat-model notes.

## Windows PowerShell setup

Run these commands from the repository root with Python 3.11 or newer:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Before creating or executing approvals, configure a secret outside source
control. For a temporary PowerShell session, this creates a fresh synthetic
development secret:

```powershell
$env:MEDISHIELD_APPROVAL_SECRET = (python -c "import secrets; print(secrets.token_hex(32))")
```

Use the team's approved secret store for any longer-lived environment. The
gateway fails closed if the variable is missing or shorter than 32 UTF-8 bytes.
Approvals created by older database versions without an authentication tag are
not accepted; create new approvals after configuring the secret. Keep this
same environment variable value in every process used by one demo session.
Do not generate a new value between creating an approval and verifying it.

The privacy workspace uses separate keys. This PowerShell block keeps the
generated values in variables without printing them:

```powershell
$receiptKeys = python -c "import base64; from cryptography.hazmat.primitives import serialization; from cryptography.hazmat.primitives.asymmetric import ed25519; k=ed25519.Ed25519PrivateKey.generate(); print(base64.urlsafe_b64encode(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode()+'|'+base64.urlsafe_b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode())"
$receiptPrivate, $receiptPublic = $receiptKeys -split '\|'
$env:MEDISHIELD_RECEIPT_SIGNING_PRIVATE_KEY = $receiptPrivate
$env:MEDISHIELD_RECEIPT_SIGNING_PUBLIC_KEY = $receiptPublic
$env:MEDISHIELD_RECEIPT_SIGNING_KEY_ID = 'demo-receipt-key'
$checkpointKeys = python -c "import base64; from cryptography.hazmat.primitives import serialization; from cryptography.hazmat.primitives.asymmetric import ed25519; k=ed25519.Ed25519PrivateKey.generate(); print(base64.urlsafe_b64encode(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode()+'|'+base64.urlsafe_b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode())"
$checkpointPrivate, $checkpointPublic = $checkpointKeys -split '\|'
$env:MEDISHIELD_AUDIT_CHECKPOINT_PRIVATE_KEY = $checkpointPrivate
$env:MEDISHIELD_AUDIT_CHECKPOINT_PUBLIC_KEY = $checkpointPublic
$env:MEDISHIELD_AUDIT_CHECKPOINT_KEY_ID = 'demo-checkpoint-key'
```

Receipt signing and audit-checkpoint signing use different Ed25519 key pairs.
Missing keys fail closed; the application does not generate or persist a
fallback key.

For Bash:

```bash
export MEDISHIELD_APPROVAL_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

If PowerShell blocks activation, use the team's approved execution-policy
setting or run the commands from an already activated virtual environment.

## Tests

```powershell
python -m pytest -q
```

Tests use temporary SQLite databases and temporary JSONL paths where state
isolation matters. They do not require real patient data or external services.

## Run the MCP server

The server uses the official FastMCP API and stdio transport. The API shape is
documented in the [MCP Python SDK v1 documentation](https://py.sdk.modelcontextprotocol.io/v1/):

```powershell
python -m server.mcp_server
```

To launch MCP Inspector against that stdio server, use a second PowerShell
window after installing Node.js and `npx`:

```powershell
npx -y @modelcontextprotocol/inspector python -m server.mcp_server
```

For a CLI tool listing:

```powershell
npx -y @modelcontextprotocol/inspector --cli python -m server.mcp_server --method tools/list
```

The repository exposes `get_patient_record`, `propose_medication_order`,
`request_clinician_approval`, `execute_approved_order`, and
`get_security_events`. The execution wrapper constructs an
`ExecutionRequest` with policy tool `update_order` and delegates to the
gateway. The read-only Python helper
`server.mcp_server.get_tool_integrity_status()` exposes the sentinel result
without adding another MCP tool.

Direct calls to protected patient-record, approval, execution, and event tools
require a trusted local-demo context. That context resolves the actor and
organization against SQLite; it is a test/demo adapter, not a real login
system. A future transport adapter must establish it from an authenticated
session rather than accepting an agent's identity claim.

Inspect the declared registry directly:

```powershell
python -c "from pprint import pprint; from server.mcp_server import get_tool_integrity_status; pprint(get_tool_integrity_status())"
```

## Run the dashboard

```powershell
python -m streamlit run dashboard/app.py
```

The dashboard uses the same repository-root SQLite path as the server and
gateway. Rendering the verification page does not execute an order; execution
requires pressing its explicit gateway-check button. The test lab buttons call
the real isolated attack functions.

## Run the synthetic demo

Run the protected scenarios from PowerShell:

```powershell
python -c "from pprint import pprint; from demo.attacks import guard_off_vs_guard_on; pprint(guard_off_vs_guard_on())"
```

The guard-off comparison is intentionally vulnerable, uses temporary synthetic
databases, and directly calls the simulated backend only to demonstrate what
the protected path prevents. It is not used by the MCP server or normal
protected execution. The guard-on side uses the actual gateway and should show
the tampered action blocked with unchanged protected state.

For the tool-registry demonstration, run:

```powershell
python -c "from pprint import pprint; from demo.attacks import tool_registry_tampering; pprint(tool_registry_tampering())"
```

This uses an in-memory altered declaration in a temporary database, reports
the unexpected tool and fingerprints, blocks through the real gateway, shows
unchanged order/approval state, restores the expected registry, and then shows
normal approved execution. It never executes injected code or modifies the
trusted source baseline.

The helper also dispatches a synthetic patient-record request through the
protected handler. The tampered registry is denied before the handler is
invoked; the result includes the handler counter, returned-data flag, audit
evidence, and the post-restore authorized result.

## Threat model and limitations

MediShield defends this prototype's execution boundary against modified
structured actions, replayed/expired/revoked approvals, unauthorized actors,
missing or mismatched destinations, and a changed registered tool fingerprint.
Prompt-injection text is not treated as an action field and cannot replace the
structured request. Registry matching only covers declared tool names, schemas,
and interface metadata. It cannot prove that the implementation, remote
server, dependencies, or runtime behavior are safe.

The fingerprint is a small synthetic baseline, not a complete defense against
all tool poisoning. The demo has no real EHR, identity provider, network
authentication, external key management, clinical validation, or multi-process
audit coordination. The approval secret authenticates rows only while it is
kept outside the agent and repository; it is not a key-management system.
SQLite and a JSONL file cannot be committed as one ordinary atomic transaction,
so filesystem failure is surfaced and protected execution fails closed. The
audit verifier provides tamper evidence across the two mutable stores, not
immutable storage. This project must remain synthetic and demo-only.

Forensic evidence can be read without changing state:

```powershell
python -c "from pprint import pprint; from guard.forensics import evidence_for_request; pprint(evidence_for_request('REQ-TO-INSPECT'))"
```

The evidence reader references an existing audit event and avoids copying the
protected action fields.

To create and verify a signed audit checkpoint after writing events:

```powershell
python -c "from server.db import initialize_db; from guard.checkpoints import create_checkpoint, verify_latest_checkpoint; c=initialize_db(); p=create_checkpoint(c); print(verify_latest_checkpoint(c)['status']); c.close()"
```

The checkpoint signs the current SQLite audit-ledger head and detects later
ledger changes. The checkpoint file is ordinary mutable filesystem storage, so
it is tamper-evident only while the signing public key and an independent copy
of the checkpoint are protected.

## AI-use disclosure

AI assistance was used for repository inspection, boilerplate review, test
scaffolding, documentation drafting, and identifying focused regression cases.
The team reviewed the security-sensitive intent and gateway behavior, ran the
tests, and owns the final implementation. The core functions are treated as
team-owned security code and are not delegated to an AI runtime.

## References

These are references for ideas and security guidance, not evidence that code
was copied or that every recommendation was implemented:

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)
- [mcpwall](https://github.com/behrensd/mcpwall)
- [mcp-firewall](https://github.com/NeuZhou/mcp-firewall)
- [Snyk Agent Scan](https://github.com/snyk/agent-scan)
- [MCP Inspector](https://github.com/modelcontextprotocol/inspector)

## Verification record

Verification for the current hardening checkout:

- Literal `python -m pytest -q` was attempted and could not complete in this
  managed environment: `55 passed, 59 errors`; the errors were fixture setup
  `PermissionError` failures scanning the restricted
  `C:\Users\Lenovo\AppData\Local\Temp\pytest-of-Lenovo` directory and the
  repository `.pytest_cache`.
- Full suite: `114 passed in 5.51s` using the bundled runtime and
  `python -m pytest -q -p no:cacheprovider --basetemp work\final-final-temp`.
- Focused security/MCP/privacy/attack command: `102 passed in 4.06s`.
- Evidence-only command: `7 passed in 0.58s`.
- Tests cover approval authentication, strict canonicalization, output-schema
  drift, patient-handler non-invocation, audit integrity, signed checkpoints,
  signed privacy receipts, deletion tombstones, and alternate-dispatch
  authorization.

The normal commands above use an activated team virtual environment. In this
managed environment, the repository `.venv` executable was inaccessible, so
the recorded runs used the bundled runtime with temporary package paths.
Streamlit was importable from the bundled test packages, but a full dashboard
browser/session launch was not performed. MCP Inspector was not run end to end;
confirm both on the team's clean Windows environment before the live demo. The
installed bundled SDK used for Sentinel inspection was MCP 1.30.0; install the
declared `mcp>=1.9,<2.0` range in the team environment and verify the resolved
version there.

## Synthetic privacy workspace

Configure the two separate document-vault keys in the same PowerShell session
before uploading or pseudonymizing a document:

```powershell
$env:MEDISHIELD_DOCUMENT_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:MEDISHIELD_PSEUDONYM_SECRET = (python -c "import secrets; print(secrets.token_hex(32))")
```

Keep both values for the entire demo session. Do not commit or unnecessarily
print them. Missing or malformed keys fail closed. `MEDISHIELD_DOCUMENT_KEY`
protects originals and derivatives with AES-256-GCM; the separate
`MEDISHIELD_PSEUDONYM_SECRET` is only needed for pseudonymization mode.

The `Secure Document Vault` page uses the same repository-root SQLite database
and stores encrypted files under the ignored `.medishield_vault/` directory.
Select a seeded synthetic local-demo identity, upload a TXT/PDF/PNG/JPEG file,
inspect the privacy report, approve it as `privacy_1`, and retrieve only the
role-permitted variant. This identity selector is not a production identity
provider. Unavailable malware scanning and image OCR remain explicit review
limitations, not successful security checks.

To run the isolated backend workflow without the UI:

```powershell
python -c "from pprint import pprint; from demo.attacks import document_vault_workflow; pprint(document_vault_workflow())"
```

The workflow uses temporary synthetic state and demonstrates upload, local
rule-based detection/redaction, encrypted storage, privacy approval, authorized
derivative retrieval, and ciphertext tamper detection. Document operations are
intentionally not added to the existing five-tool MCP registry in this patch;
adding them requires a separately reviewed Trust Sentinel baseline update.

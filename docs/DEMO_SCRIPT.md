# MediShield 3–5 minute demo script

Use only a freshly verified checkout and synthetic data.

## Before starting — configure the approval secret

Approval creation and gateway verification must use the same secret. In one
PowerShell session, run this once and keep that session/environment for the
dashboard, MCP server, and demo commands:

```powershell
$env:MEDISHIELD_APPROVAL_SECRET = (python -c "import secrets; print(secrets.token_hex(32))")
$env:MEDISHIELD_DOCUMENT_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:MEDISHIELD_PSEUDONYM_SECRET = (python -c "import secrets; print(secrets.token_hex(32))")
```

Privacy receipt and audit-checkpoint signing use separate Ed25519 key pairs.
Generate each pair once per demo session and keep the values in memory:

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

Do not print the values or generate replacements during the same demo session.
The gateway intentionally fails closed when the variable is absent or invalid.
For Bash, run:

```bash
export MEDISHIELD_APPROVAL_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export MEDISHIELD_DOCUMENT_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export MEDISHIELD_PSEUDONYM_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

## 0:00–0:30 — Set the scene

“MediShield is a runtime gateway between an AI-agent-style caller and a
simulated clinical backend. The agent can propose and submit an action, but a
clinician approves one exact structured action first.”

Start the MCP server or dashboard using the commands in `docs/README.md`.

## 0:30–1:10 — Show the Trust Sentinel

Run the read-only status helper:

```powershell
python -c "from pprint import pprint; from server.mcp_server import get_tool_integrity_status; pprint(get_tool_integrity_status())"
```

Point out the expected and observed fingerprints and the five declared tools.
Explain that this validates the declared registry, not the complete remote
implementation.

## 1:10–1:55 — Show the normal flow

1. Show the synthetic patient and the structured order fields.
2. Propose the order; point out that proposal does not change the backend.
3. Create an approval as `clinician_1`.
4. Execute the exact action as `agent_1`.
5. Show the allowed decision, changed state, consumed approval, and audit event.

## 1:55–2:45 — Show attacks

Run the test-lab scenarios or the equivalent tests:

```powershell
python -m pytest -q tests/test_attacks.py tests/test_gateway_security.py
```

Demonstrate dose tampering first, then patient substitution or replay. Explain
that the gateway recomputes the protected-action digest and checks approval
state, actor role, and destination before the order writer is reached.

## 2:45–3:35 — Demonstrate tool-registry tampering

Run:

```powershell
python -c "from pprint import pprint; from demo.attacks import tool_registry_tampering; pprint(tool_registry_tampering())"
```

Show the simulated unexpected tool, the changed fingerprint, the blocked
gateway decision, and unchanged order/approval state. Then show that restoring
the expected registry permits the exact still-unused approval. Emphasize that
the altered fixture is in memory and no injected code runs.

## 4:10–4:40 — Compare guard-off and guard-on

Click “Compare guard-off vs guard-on” or run:

```powershell
python -c "from pprint import pprint; from demo.attacks import guard_off_vs_guard_on; pprint(guard_off_vs_guard_on())"
```

The isolated guard-off path directly changes a temporary synthetic backend.
The same tampered action on the guard-on path is sent through the real gateway
and is blocked with unchanged state. The baseline is intentionally vulnerable
and is never the normal application path.

## 4:40–5:10 — Show the document privacy workflow (optional extension)

With the three environment variables configured, run the isolated workflow:

```powershell
python -c "from pprint import pprint; from demo.attacks import document_vault_workflow; pprint(document_vault_workflow())"
```

Point out the actual pending-review status, category/count-only report, local
redacted derivative, reviewer approval, researcher retrieval, and tamper
detection. The demo uses a temporary SQLite database and vault. It does not
claim complete de-identification. The dashboard's `Secure Document Vault` page
shows the same service with seeded local-demo identities; the selector is not
production authentication.

## 4:10–4:50 — Show audit and limitations

Show the SQLite audit event and the matching JSONL line. Mention that the log
and database are separate stores, so filesystem failure is surfaced rather than
reported as a successful protected execution. Close with the limitations: no
real patients, no real EHR, no identity provider, registry matching cannot
prove implementation safety, and no claim of regulatory compliance. If time
allows, read the incident with `evidence_for_request()` and point to its audit
event reference and fingerprints.

## Before presenting

Run `python -m pytest -q` and read the actual final output aloud. Do not use a
historical count. The MCP Inspector end-to-end status must also be stated
truthfully: “verified” only if the team ran the Inspector command successfully;
otherwise say “to confirm” and use the direct gateway/dashboard fallback.

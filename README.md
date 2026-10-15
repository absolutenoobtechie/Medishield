# MediShield

Synthetic HackUrity 2026 Track A prototype: a runtime gateway that checks a
clinician-approved exact action before a simulated backend update.

The Trust Sentinel also verifies the declared MCP tool registry before protected
execution and records forensic context when registry drift blocks a request.

Approvals also carry a gateway-controlled authentication tag. Set
`MEDISHIELD_APPROVAL_SECRET` to a secret of at least 32 UTF-8 bytes before
creating or executing approvals; never commit that value.

Start with [docs/README.md](docs/README.md) for Windows PowerShell setup,
tests, MCP Inspector, dashboard, demo, threat model, and limitations.

## Synthetic privacy workspace

The local MVP also provides a tenant-scoped document vault. TXT and PDF text
can be processed with local rule-based PHI detection; PNG/JPEG files are
stored encrypted but remain manual-review items because OCR is not configured.
Originals and text derivatives use AES-256-GCM, and stored content is
SHA-256-verified before retrieval. The service requires
`MEDISHIELD_DOCUMENT_KEY`; pseudonymization additionally requires the separate
`MEDISHIELD_PSEUDONYM_SECRET`. There is no fallback key.

The current workspace identity selector is explicitly local-demo
authentication, not a production identity provider. Document operations are
enforced in the backend service and integrated into the dashboard. They are
not exposed as additional MCP tools in this patch, because changing the
reviewed five-tool Trust Sentinel baseline requires a separate reviewed MCP
registry change; the safe direct-service/dashboard path is documented.

Processed documents receive signed non-content receipts, and the audit store
can be anchored with a separate signed checkpoint. These are verification aids,
not immutable storage, complete de-identification, or regulatory compliance.

Direct clinical backend helpers fail closed without a server-resolved local
demo context. Patient and approval operations re-check the actor's active role
and organization in SQLite; supplying an actor ID or role string by itself is
not authorization. The local identity adapter is suitable only for the
synthetic demonstration and must be replaced by an authenticated session for
any deployment beyond this prototype.

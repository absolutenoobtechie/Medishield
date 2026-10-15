# MediShield contributor notes

## Goal

MediShield is a runtime security gateway between an AI agent and a simulated clinical backend. It is a guard, not a general-purpose toolkit. All data in this project is synthetic and for the hackathon demo only.

## Folder owners

- Person 1: `guard/`
- Person 2: `server/`
- Person 3: `dashboard/`
- Person 4: `tests/` and `demo/`

## Rules

- Fail closed: an unknown, invalid, expired, revoked, or changed request must not execute.
- Never trust a hash supplied by the agent. Recompute it from the protected action at the gateway.
- The canonical hash must use sorted, compact JSON, Decimal-normalised `dose`, and lowercase `units`.
- Compare hashes with `hmac.compare_digest`.
- The action hash is only a content fingerprint. Approval authenticity uses a
  gateway-controlled HMAC key from `MEDISHIELD_APPROVAL_SECRET`; never fall
  back to a plain hash or a source-controlled default when that key is absent.
- Supported unit aliases are explicit and unknown units fail closed.
- The protected dose input is a string, must be finite and positive, and is
  limited to 64 characters and a value of at most 1,000,000 for this demo.
- The default SQLite database is repository-root based so changing the
  working directory does not silently select a second application database.
- The SQLite `tool_baseline` row for `update_order` must exist and match the
  trusted synthetic fingerprint and destination before execution.
- `apply_order` is the sole order writer and requires the private gateway
  capability; the guard-off demo may use it only inside its isolated synthetic
  fixture.
- The MCP registry baseline is explicit and reviewed in `guard/sentinel.py`;
  never learn or overwrite it from an observed registry at runtime.
- AI is for boilerplate only. The team writes the two core security functions by hand:
  - `guard/intent.py`: `canonicalize_action` and `action_hash`
  - `guard/gateway.py`: `verify_execution`
- Do not add FastAPI, an LLM, or libraries beyond `requirements.txt` without team agreement.

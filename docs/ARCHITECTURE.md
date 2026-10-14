# MediShield architecture and security notes

## Components

1. The MCP wrapper accepts structured synthetic tool calls.
2. `server/backend.py` creates and revokes clinician approvals and exposes the
   synthetic order state.
3. `guard/gateway.py` is the only protected execution decision point.
4. `server/backend.apply_order()` is the only function that writes the
   `orders` table and requires the gateway's caller-owned transaction.
5. `guard/audit.py` writes the contract event to SQLite and appends the same
   JSON object to `logs/events.jsonl`.
6. The Streamlit dashboard reads the shared repository-root database and calls
   the same gateway/demo functions used by the tests.

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
to detect every tool-description or supply-chain attack.

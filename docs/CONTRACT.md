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

## `verify_execution` check order

The gateway checks, in this order:

1. Validate the request schema and all protected fields.
2. Validate the actor's role.
3. Pin the policy tool, the SQLite tool baseline, its fingerprint, and its exact destination.
4. Validate that the approval exists, is unexpired, is not revoked, is not consumed, and was issued by a clinician.
5. Recompute the protected-action hash and compare it with the stored approval hash.
6. Atomically consume the approval, write the order through `apply_order`, and write the audit event.
7. Audit every outcome that can be persisted safely.
8. Fail closed whenever a check, backend write, or audit write cannot be completed safely.

The MCP tool `execute_approved_order` always uses the policy name
`update_order` and delegates to `verify_execution`; it does not write the
`orders` table directly.

## Folder ownership

- Person 1 owns `guard/`.
- Person 2 owns `server/`.
- Person 3 owns `dashboard/`.
- Person 4 owns `tests/` and `demo/`.

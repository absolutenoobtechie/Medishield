# MediShield contract

## Audit event format

Every execution outcome must produce one audit event, including blocked and
invalid requests. The event has these fields:

| Field | Allowed values or meaning |
| --- | --- |
| `time` | UTC timestamp |
| `request_id` | Request identifier |
| `actor` | Actor identifier |
| `tool` | MCP tool name |
| `action_type` | Requested operation |
| `approval_id` | Approval identifier, when present |
| `decision` | `allowed`, `blocked`, or `warning` |
| `risk` | `low`, `medium`, or `high` |
| `rule` | Rule that produced the decision |
| `reason` | Plain-language explanation |
| `changed_fields` | List of protected fields that changed |
| `state_changed` | `true` or `false` |

## Tables

- `actors(actor_id, role)`
- `patients(patient_id, name_synthetic)`
- `approvals(approval_id, action_hash, action_json, approver_id, created_at, expires_at, revoked, consumed)`
- `orders(order_id, patient_id, medication_id, dose, units, route, frequency, duration)`
- `audit_events(id, time, request_id, actor_id, tool, action_type, approval_id, decision, risk, rule, reason, changed_fields, state_changed)`
- `tool_baseline(tool_name, fingerprint, allowed_destination)`

## `verify_execution` check order

The eventual gateway implementation must check, in this order:

1. Validate the request schema.
2. Validate the actor's role.
3. Pin the tool and its allowed destination.
4. Validate that the approval exists, is unexpired, is not revoked, and is not consumed.
5. Recompute the protected-action hash and compare it with the stored approval hash.
6. Atomically consume the approval and write the backend state.
7. Audit every outcome.
8. Fail closed whenever a check cannot be completed safely.

## Folder ownership

- Person 1 owns `guard/`.
- Person 2 owns `server/`.
- Person 3 owns `dashboard/`.
- Person 4 owns `tests/` and `demo/`.

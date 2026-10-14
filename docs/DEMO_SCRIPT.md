# MediShield 3–5 minute demo script

Use only a freshly verified checkout and synthetic data.

## 0:00–0:30 — Set the scene

“MediShield is a runtime gateway between an AI-agent-style caller and a
simulated clinical backend. The agent can propose and submit an action, but a
clinician approves one exact structured action first.”

Start the MCP server or dashboard using the commands in `docs/README.md`.

## 0:30–1:20 — Show the normal flow

1. Show the synthetic patient and the structured order fields.
2. Propose the order; point out that proposal does not change the backend.
3. Create an approval as `clinician_1`.
4. Execute the exact action as `agent_1`.
5. Show the allowed decision, changed state, consumed approval, and audit event.

## 1:20–2:45 — Show attacks

Run the test-lab scenarios or the equivalent tests:

```powershell
python -m pytest -q tests/test_attacks.py tests/test_gateway_security.py
```

Demonstrate dose tampering first, then patient substitution or replay. Explain
that the gateway recomputes the protected-action digest and checks approval
state, actor role, and destination before the order writer is reached.

## 2:45–3:30 — Compare guard-off and guard-on

Click “Compare guard-off vs guard-on” or run:

```powershell
python -c "from pprint import pprint; from demo.attacks import guard_off_vs_guard_on; pprint(guard_off_vs_guard_on())"
```

The isolated guard-off path directly changes a temporary synthetic backend.
The same tampered action on the guard-on path is sent through the real gateway
and is blocked with unchanged state. The baseline is intentionally vulnerable
and is never the normal application path.

## 3:30–4:30 — Show audit and limitations

Show the SQLite audit event and the matching JSONL line. Mention that the log
and database are separate stores, so filesystem failure is surfaced rather than
reported as a successful protected execution. Close with the limitations: no
real patients, no real EHR, no identity provider, and no claim of regulatory
compliance.

## Before presenting

Run `python -m pytest -q` and read the actual final output aloud. Do not use a
historical count. The MCP Inspector end-to-end status must also be stated
truthfully: “verified” only if the team ran the Inspector command successfully;
otherwise say “to confirm” and use the direct gateway/dashboard fallback.

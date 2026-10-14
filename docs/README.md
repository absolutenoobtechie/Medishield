# MediShield

MediShield is a HackUrity 2026 Track A demonstration of a runtime security
gateway between an AI-agent-style caller and a simulated clinical backend. All
patients, orders, actors, and events are synthetic. This is not medical advice,
not a clinical system, and not a regulatory-compliance claim.

The central control is the Clinical Intent Lock: a clinician approves one exact
structured action, and the gateway recomputes the action hash at execution time.
An altered dose, patient, medication, route, frequency, duration, or order ID
does not match the approval and is blocked. Approvals are also time-limited,
revocable, and single-use.

## Architecture

The project is intentionally small:

- `guard/` contains the strict models, action canonicalization and hashing,
  policy checks, gateway transaction, and audit persistence.
- `server/` contains the SQLite setup, synthetic backend, approval functions,
  and FastMCP wrapper.
- `dashboard/` contains the Streamlit demonstration UI.
- `demo/` contains isolated synthetic attack scenarios, including the clearly
  labeled guard-off versus guard-on comparison.
- `tests/` contains gateway, backend, audit, MCP, smoke, and attack tests.

The protected flow is:

`propose action` → `clinician approval record` → `MCP execution request` →
`gateway validation and pinning` → `hash comparison` → `single-use consume +
order update + audit`.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [CONTRACT.md](CONTRACT.md) for the
field-level contract and threat-model notes.

## Windows PowerShell setup

Run these commands from the repository root with Python 3.11 or newer:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
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
gateway.

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

## Threat model and limitations

MediShield defends this prototype's execution boundary against modified
structured actions, replayed/expired/revoked approvals, unauthorized actors,
missing or mismatched destinations, and a changed registered tool fingerprint.
Prompt-injection text is not treated as an action field and cannot replace the
structured request.

The fingerprint is a small synthetic baseline, not a complete defense against
all tool poisoning. The demo has no real EHR, identity provider, network
authentication, key management, clinical validation, or multi-process audit
coordination. SQLite and a JSONL file cannot be committed as one ordinary
atomic transaction, so filesystem failure is surfaced and protected execution
fails closed. This project must remain synthetic and demo-only.

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

Final verification on 2026-10-14:

- Focused security/backend/audit/attack/MCP command: `47 passed in 1.33s`.
- Full suite command: `49 passed in 2.27s`.
- Streamlit AppTest: `0` exceptions and `9` buttons.
- Live `python -m streamlit run dashboard/app.py --server.headless true`
  startup reached the running-server state and was then stopped after the
  smoke check.
- FastMCP registration listed all five required tools.

The normal commands above use an activated team virtual environment. In this
managed environment, the repository `.venv` executable was inaccessible and
the `pytest` command was not on PATH, so the recorded runs used the bundled
Python runtime with temporary package paths and an isolated pytest temp
directory. MCP Inspector was not tested end to end here because its `npx`
startup hit a Windows sandbox `EPERM` error; direct FastMCP registration and
direct tool-function tests passed. Confirm Inspector on the team's machine
before relying on it for the live demo. The bundled SDK check exercised MCP
1.30.0; an isolated exact-MCP-1.9.0 check did not import successfully with the
available Pydantic environment. The declared `mcp>=1.9,<2.0` range should be
installed normally in the team's clean virtual environment, and the team
should pin a tested resolved version if the lower bound is required.

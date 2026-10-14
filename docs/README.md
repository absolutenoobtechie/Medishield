# MediShield

MediShield is a hackathon scaffold for a runtime security gateway between an
AI agent and a simulated clinical backend. All values are synthetic. The
Clinical Intent Lock is intentionally not implemented yet: a clinician will
approve one exact action, and the gateway will later recompute and compare its
protected-action hash at execution time.

## Windows PowerShell setup

From the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest
python -m streamlit run dashboard/app.py
```

If PowerShell blocks activation, use the team's approved execution-policy
setting or run the commands from an already activated virtual environment.

## Current scope

This commit contains contracts, SQLite setup, synthetic sample events, and
placeholders only. It does not add FastAPI, an LLM, MCP tools, or security
logic.

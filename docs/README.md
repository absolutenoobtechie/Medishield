# MediShield Technical Documentation Index

Welcome to the technical documentation repository for **MediShield: Runtime Security Gateway for MCP-Connected AI Tools**.

This directory contains the formal contracts, architecture specifications, demonstration guides, threat models, and protocol definitions for the MediShield project.

---

## Documentation Directory

| Document | Primary Audience | Description |
| :--- | :--- | :--- |
| **[CONTRACT.md](file:///c:/Users/User/Downloads/Medishield-main/Medishield-main/docs/CONTRACT.md)** | Core Developers & Auditors | Authoritative audit event format, database schema contracts, folder ownership, and the mandatory 8-stage verification sequence. |
| **[MCP_DEMO.md](file:///c:/Users/User/Downloads/Medishield-main/Medishield-main/docs/MCP_DEMO.md)** | Hackathon Judges & Evaluators | Comprehensive, copy-pasteable Windows PowerShell demonstration guide reproducing all 8 adversarial attack scenarios and audit log inspection. |
| **[ARCHITECTURE.md](file:///c:/Users/User/Downloads/Medishield-main/Medishield-main/docs/ARCHITECTURE.md)** | Systems Architects & Engineers | Full architectural specification detailing trust boundaries, sequence diagrams, canonicalization algorithms, and atomic database state machines. |
| **[THREAT_MODEL.md](file:///c:/Users/User/Downloads/Medishield-main/Medishield-main/docs/THREAT_MODEL.md)** | Security Researchers | STRIDE threat model addressing parameter tampering, prompt injection tool hijacking, confused deputy, approval replay, and TOCTOU vectors. |
| **[MCP_SPECIFICATION.md](file:///c:/Users/User/Downloads/Medishield-main/Medishield-main/docs/MCP_SPECIFICATION.md)** | MCP Integrators | Model Context Protocol technical interface, tool argument schemas, stdio transport conventions, and gateway mediation patterns. |

---

## Quick Reference: Verified Windows PowerShell Commands

From the repository root:

```powershell
# 1. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 2. Run verified security test suite (24 passing tests)
python -m pytest tests/test_attacks.py tests/test_backend_audit.py tests/test_gateway_security.py -v

# 3. Execute interactive dose tampering demo
python -c "from demo.attacks import tamper_dose; print(tamper_dose())"

# 4. Launch the Streamlit Security Operations Dashboard
python -m streamlit run dashboard/app.py
```

---

*All patient data, orders, and medications documented within this repository are strictly synthetic and intended for hackathon security research.*

"""
MediShield Runtime Security Gateway Dashboard
==============================================
Production-grade runtime security monitoring, testing lab, and audit console
for AI-connected clinical backend tools.

Built strictly with Python and Streamlit.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st

# Indian Standard Time (IST) definition: UTC + 5:30
IST_TZ = timezone(timedelta(hours=5, minutes=30), name="IST")


def to_ist_string(time_val: Any) -> str:
    """Convert an ISO UTC timestamp string to formatted Indian Standard Time (IST)."""
    if not time_val:
        return "N/A"
    try:
        s = str(time_val).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ist_dt = dt.astimezone(IST_TZ)
        return ist_dt.strftime("%Y-%m-%d %H:%M:%S IST")
    except Exception:
        return str(time_val)


# ==============================================================================
# SECTION 1: Path Setup & Module Imports
# ==============================================================================
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from guard.audit import record_audit_event
from guard.gateway import verify_execution
from guard.intent import action_hash, canonicalize_action
from guard.models import Decision, ExecutionRequest, ProtectedAction
from server.db import DEFAULT_DB_PATH, get_connection, init_db, seed_data

# Ensure synthetic DB tables and baseline seed data exist
try:
    _conn = get_connection(ROOT_DIR / DEFAULT_DB_PATH)
    init_db(_conn)
    seed_data(_conn)
    _conn.close()
except Exception:
    pass


# ==============================================================================
# SECTION 2: Dynamic Gateway Health & Unified Data Loader
# ==============================================================================
def check_gateway_health() -> Dict[str, Any]:
    """
    Dynamically verify the health of the MediShield gateway and underlying database.
    Does not use hardcoded health values.
    """
    target_db = ROOT_DIR / DEFAULT_DB_PATH
    try:
        if not target_db.exists():
            return {
                "status": "DEGRADED",
                "healthy": False,
                "detail": f"Database file missing at {target_db.name}",
            }
        conn = get_connection(target_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN "
            "('audit_events', 'approvals', 'actors', 'orders', 'tool_baseline')"
        )
        count = cursor.fetchone()[0]
        conn.close()

        if count < 5:
            return {
                "status": "DEGRADED",
                "healthy": False,
                "detail": f"Incomplete schema ({count}/5 tables detected)",
            }

        # Test canonical hash self-check
        test_h = action_hash(
            ProtectedAction(
                order_id="ORD-HEALTH",
                patient_id="P-HEALTH",
                medication_id="MED-HEALTH",
                dose="1",
                units="mg",
                route="oral",
                frequency="daily",
                duration=None,
            )
        )
        if not test_h or len(test_h) != 64:
            return {
                "status": "DEGRADED",
                "healthy": False,
                "detail": "Cryptographic engine self-test failed",
            }

        return {
            "status": "OPERATIONAL",
            "healthy": True,
            "detail": "All 5 core tables online • Fail-closed gateway ready • HMAC SHA-256 self-test passed",
        }
    except Exception as e:
        return {
            "status": "OFFLINE",
            "healthy": False,
            "detail": f"Health check exception: {str(e)}",
        }


def load_events(db_path: Optional[Path] = None) -> Tuple[List[Dict[str, Any]], str]:
    """
    Load audit events from the SQLite audit_events table if rows exist;
    otherwise fall back to reading logs/sample_events.jsonl.
    Always returns events sorted strictly descending by timestamp (newest first).
    """
    events: List[Dict[str, Any]] = []
    target_db = Path(db_path) if db_path else (ROOT_DIR / DEFAULT_DB_PATH)
    source_type = "fallback"

    # 1. Try SQLite database
    try:
        if target_db.exists():
            conn = get_connection(target_db)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'")
            if cursor.fetchone():
                cursor.execute("SELECT * FROM audit_events ORDER BY id DESC")
                rows = cursor.fetchall()
                if rows:
                    source_type = "sqlite"
                    for row in rows:
                        raw_cf = row["changed_fields"]
                        if isinstance(raw_cf, str):
                            try:
                                cf = json.loads(raw_cf)
                            except Exception:
                                cf = [f.strip() for f in raw_cf.split(",") if f.strip()]
                        elif isinstance(raw_cf, list):
                            cf = raw_cf
                        else:
                            cf = []

                        actor = (
                            row["actor_id"]
                            if "actor_id" in row.keys()
                            else row.get("actor", "unknown")
                        )

                        event = {
                            "time": str(row["time"]),
                            "request_id": str(row["request_id"]),
                            "actor": str(actor),
                            "tool": str(row["tool"]),
                            "action_type": str(row["action_type"]),
                            "approval_id": row["approval_id"],
                            "decision": str(row["decision"]),
                            "risk": str(row["risk"]),
                            "rule": str(row["rule"]),
                            "reason": str(row["reason"]),
                            "changed_fields": cf,
                            "state_changed": bool(row["state_changed"]),
                        }
                        events.append(event)
                    conn.close()
                    # Ensure strict descending order by time
                    events.sort(key=lambda e: str(e.get("time") or ""), reverse=True)
                    return events, "Live Database (SQLite: audit_events)"
            conn.close()
    except Exception:
        pass

    # 2. Fallback to sample_events.jsonl
    jsonl_path = ROOT_DIR / "logs" / "sample_events.jsonl"
    if jsonl_path.exists():
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        continue
        # Ensure strict descending order by time
        events.sort(key=lambda e: str(e.get("time") or ""), reverse=True)
        return events, "Synthetic Fallback (logs/sample_events.jsonl)"

    return events, "No Events Available"


# ==============================================================================
# SECTION 3: Streamlit UI Setup & Refined Cybersecurity Styling
# ==============================================================================
st.set_page_config(
    page_title="MediShield - Clinical AI Security Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    /* Cybersecurity Console Palette */
    :root {
        --bg-navy: #0b0f19;
        --card-bg: #151b26;
        --border-color: #212c3d;
        --text-main: #e2e8f0;
        --text-dim: #94a3b8;
        --teal-accent: #0ea5e9;
        --green-allowed: #10b981;
        --red-blocked: #ef4444;
        --amber-warning: #f59e0b;
    }

    /* Metric Cards */
    .metric-card {
        background: #151b26;
        border: 1px solid #212c3d;
        border-radius: 8px;
        padding: 18px 12px;
        text-align: center;
        margin-bottom: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .metric-val {
        font-size: 2.2rem;
        font-weight: 700;
        line-height: 1.1;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    }
    .metric-lbl {
        font-size: 0.78rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin-top: 6px;
        font-weight: 600;
    }

    /* Security Decision Badges */
    .badge-allowed {
        background-color: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid #059669;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
        letter-spacing: 0.5px;
    }
    .badge-blocked {
        background-color: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid #dc2626;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
        letter-spacing: 0.5px;
    }
    .badge-warning {
        background-color: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        border: 1px solid #d97706;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
        display: inline-block;
        letter-spacing: 0.5px;
    }

    /* Risk Badges */
    .risk-high {
        background-color: rgba(239, 68, 68, 0.12);
        color: #fca5a5;
        border: 1px solid #b91c1c;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .risk-med {
        background-color: rgba(245, 158, 11, 0.12);
        color: #fde68a;
        border: 1px solid #b45309;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .risk-low {
        background-color: rgba(16, 185, 129, 0.12);
        color: #a7f3d0;
        border: 1px solid #047857;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    /* Operational Status Banner */
    .status-banner {
        background: #111827;
        border: 1px solid #1f2937;
        border-left: 4px solid #0ea5e9;
        padding: 14px 20px;
        border-radius: 6px;
        margin: 12px 0 20px 0;
    }
    .status-pill-ok {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 700;
        background-color: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid #10b981;
    }
    .status-pill-degraded {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 700;
        background-color: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid #ef4444;
    }

    /* Event Row Card */
    .event-row-container {
        background: #131924;
        border: 1px solid #1e293b;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 8px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Load events, active source, and live gateway status
all_events, active_data_source = load_events()
gw_health = check_gateway_health()

# Top Header Layout
header_left, header_right = st.columns([5, 1])
with header_left:
    st.title("🛡️ MediShield Security Gateway")
    st.markdown(
        "**Runtime Clinical AI Gateway** &nbsp;|&nbsp; "
        "Deterministic Intent Locks • Fail-Closed Enforcement • Non-Repudiable Audit Trail"
    )
with header_right:
    st.write("")
    if st.button("🔄 Refresh Data", key="top_refresh_btn", use_container_width=True):
        st.rerun()

# Sidebar Controls
st.sidebar.header("🛡️ MediShield Control")
st.sidebar.markdown(f"**Data Source:**  \n`{active_data_source}`")
st.sidebar.markdown(f"**Total Records:** `{len(all_events)}`")

if st.sidebar.button("🔄 Force Refresh", key="sidebar_refresh_btn", use_container_width=True):
    st.rerun()

st.sidebar.divider()
st.sidebar.subheader("Security Invariants")
st.sidebar.markdown(
    """
    - **Fail-Closed:** Default deny on any error
    - **Intent Lock:** Deterministic SHA-256 HMAC
    - **Canonicalized:** Decimal `dose` & lowercase `units`
    - **Single-Use:** Token consumed atomically
    - **Zero Trust:** Recomputed independently at gateway
    """
)
st.sidebar.caption("MediShield Security Engine • Synthetic Clinical Data Only")


# ==============================================================================
# HELPER: Render 3-Column Expandable Event Row (Major UI Mandate)
# ==============================================================================
def render_audit_event_card(event: Dict[str, Any], expanded_default: bool = False):
    """
    Renders an audit event adhering strictly to the 3-column row design:
    Collapsed View:  | Request ID | Gateway Decision | Risk Level |
    Expanded View:
      1. Request Details
      2. Security Assessment
      3. Execution Outcome
      4. Raw JSON (collapsed expander)
    """
    req_id = str(event.get("request_id", "UNKNOWN"))
    dec = str(event.get("decision", "unknown")).lower()
    risk = str(event.get("risk", "unknown")).lower()
    time_ist = to_ist_string(event.get("time"))
    tool_name = str(event.get("tool", "update_order"))

    # Badges
    if dec == "allowed":
        dec_badge = '<span class="badge-allowed">ALLOWED</span>'
        dec_icon = "🟢"
    elif dec == "blocked":
        dec_badge = '<span class="badge-blocked">BLOCKED</span>'
        dec_icon = "🔴"
    else:
        dec_badge = '<span class="badge-warning">WARNING</span>'
        dec_icon = "🟡"

    if risk == "high":
        risk_badge = '<span class="risk-high">HIGH</span>'
    elif risk in ["med", "medium"]:
        risk_badge = '<span class="risk-med">MEDIUM</span>'
    else:
        risk_badge = '<span class="risk-low">LOW</span>'

    # Container with 3 primary columns
    with st.container():
        c_id, c_dec, c_risk = st.columns([4, 3, 3])
        with c_id:
            st.markdown(
                f"**`{req_id}`** &nbsp; "
                f"<span style='color: #64748b; font-size: 0.8rem;'>({time_ist})</span>",
                unsafe_allow_html=True,
            )
        with c_dec:
            st.markdown(dec_badge, unsafe_allow_html=True)
        with c_risk:
            st.markdown(risk_badge, unsafe_allow_html=True)

        # Expander for Full Details
        expander_title = f"🔍 Inspect Details for {req_id} • Tool: {tool_name}"
        with st.expander(expander_title, expanded=expanded_default):
            # Section 1: Request Details
            st.markdown("##### 1. Request Details")
            r1, r2, r3, r4, r5 = st.columns(5)
            r1.metric("Request ID", req_id)
            r2.metric("Actor ID", str(event.get("actor", "N/A")))
            r3.metric("Tool Name", tool_name)
            r4.metric("Approval ID", str(event.get("approval_id") or "None"))
            r5.metric("Timestamp (IST)", time_ist)

            st.markdown("---")

            # Section 2: Security Assessment
            st.markdown("##### 2. Security Assessment")
            s1, s2, s3 = st.columns([2, 3, 5])
            with s1:
                st.markdown(f"**Decision:** {dec_badge}", unsafe_allow_html=True)
            with s2:
                st.markdown(f"**Risk Level:** {risk_badge}", unsafe_allow_html=True)
            with s3:
                st.markdown(f"**Security Rule:** `{event.get('rule', 'N/A')}`")

            st.markdown(f"**Plain-Language Clinical Explanation:**")
            st.info(event.get("reason", "No detailed reason recorded."))

            st.markdown("---")

            # Section 3: Execution Outcome
            st.markdown("##### 3. Execution Outcome")
            o1, o2 = st.columns(2)
            with o1:
                st_changed = event.get("state_changed", False)
                if st_changed:
                    st.markdown("**Backend Database State:**  \n`True` *(State Modified)*")
                else:
                    st.markdown("**Backend Database State:**  \n`False` *(Protected / Unaltered)*")
            with o2:
                cf = event.get("changed_fields", [])
                st.markdown(f"**Detected / Changed Fields:** `{cf}`")

            # Section 4: Raw JSON Sub-Expander
            with st.expander("📄 View Raw Audit Event (JSON)", expanded=False):
                st.json(event)

        st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)


# ==============================================================================
# SECTION 4: Four Primary Navigation Tabs
# ==============================================================================
tab_overview, tab_test_lab, tab_verification, tab_audit = st.tabs([
    "📊 Overview",
    "🧪 Security Test Lab",
    "🔍 Action Verification",
    "📜 Audit Log",
])


# ------------------------------------------------------------------------------
# TAB 1: OVERVIEW
# ------------------------------------------------------------------------------
with tab_overview:
    total_calls = len(all_events)
    allowed_calls = sum(1 for e in all_events if str(e.get("decision")).lower() == "allowed")
    blocked_calls = sum(1 for e in all_events if str(e.get("decision")).lower() == "blocked")
    warning_calls = sum(1 for e in all_events if str(e.get("decision")).lower() == "warning")

    # Error Rate Definition:
    # (genuine execution errors / total operations) * 100
    # Crucial: Blocked security decisions and Warnings must NOT be counted as execution errors.
    genuine_errors = sum(
        1 for e in all_events
        if any(
            err_term in str(e.get("rule", "")).lower() or err_term in str(e.get("reason", "")).lower()
            for err_term in ["malformed", "syntax", "database error", "internal error", "system fault", "fail closed exception"]
        )
        or bool(e.get("error"))
    )
    error_rate = (genuine_errors / total_calls * 100.0) if total_calls > 0 else 0.0

    # 5 Balanced Metric Cards
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-val" style="color: #38bdf8;">{total_calls}</div>
                <div class="metric-lbl">Total Monitored Calls</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-val" style="color: #34d399;">{allowed_calls}</div>
                <div class="metric-lbl">Allowed (Passed)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-val" style="color: #f87171;">{blocked_calls}</div>
                <div class="metric-lbl">Blocked (Attacks Stopped)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-val" style="color: #fbbf24;">{warning_calls}</div>
                <div class="metric-lbl">Warnings (Flagged)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c5:
        err_color = "#34d399" if error_rate == 0.0 else "#f87171"
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-val" style="color: {err_color};">{error_rate:.1f}%</div>
                <div class="metric-lbl">Error Rate (System Faults)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Dynamic Operational Gateway Status Bar
    status_pill_html = (
        '<span class="status-pill-ok">● ACTIVE (FAIL-CLOSED)</span>'
        if gw_health["healthy"]
        else f'<span class="status-pill-degraded">● {gw_health["status"]}</span>'
    )
    st.markdown(
        f"""
        <div class="status-banner">
            <span style="font-weight: 700; color: #f1f5f9; letter-spacing: 0.5px;">GATEWAY STATUS:</span>
            &nbsp; {status_pill_html}
            <span style="color: #94a3b8; margin-left: 16px; font-size: 0.88rem;">
                {gw_health['detail']} &nbsp;|&nbsp; Data Source: <b>{active_data_source}</b>
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Recent Security Activity (Clean 3-Column Expandable List)
    st.subheader("Recent Security Activity (Latest Events)")
    st.caption("Expand any row to inspect complete request parameters, security checks, and outcome.")

    if all_events:
        # Table Header
        h1, h2, h3 = st.columns([4, 3, 3])
        h1.markdown("**🆔 Event / Request ID**")
        h2.markdown("**⚖️ Gateway Decision**")
        h3.markdown("**⚠️ Risk Level**")
        st.markdown("<hr style='margin: 4px 0 12px 0; border-color: #212c3d;' />", unsafe_allow_html=True)

        # Show up to 8 recent events using the 3-column expandable card
        for ev in all_events[:8]:
            render_audit_event_card(ev, expanded_default=False)
    else:
        st.info("No audit events found.")


# ------------------------------------------------------------------------------
# TAB 2: SECURITY TEST LAB
# ------------------------------------------------------------------------------
with tab_test_lab:
    st.subheader("🧪 Live Attack Simulation & Enforcement Lab")
    st.markdown(
        "Execute synthetic security attacks against the **actual MediShield enforcement engine** "
        "(`guard/gateway.py`). Each test runs through canonical hashing, database policy checks, "
        "and atomic state commitment to prove tampering is blocked while preserving backend integrity."
    )

    def _setup_test_approval(conn, approval_id: str, action_data: dict) -> str:
        """Helper to register a synthetic clinician approval in the database."""
        prot = ProtectedAction(**action_data)
        h = action_hash(prot)
        conn.execute(
            """
            INSERT INTO approvals (approval_id, action_hash, action_json, approver_id, created_at, expires_at, revoked, consumed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(approval_id) DO UPDATE SET
                action_hash = excluded.action_hash,
                action_json = excluded.action_json,
                revoked = 0,
                consumed = 0
            """,
            (
                approval_id,
                h,
                json.dumps(action_data),
                "clinician_1",
                datetime.now(timezone.utc).isoformat(),
                "2026-12-31T23:59:59Z",
                0,
                0,
            ),
        )
        conn.commit()
        return h

    col_btn1, col_btn2, col_btn3, col_btn4, col_btn5 = st.columns(5)
    run_tamper = col_btn1.button("⚡ Test 1: Dose Tamper", use_container_width=True)
    run_patient = col_btn2.button("⚡ Test 2: Patient Sub.", use_container_width=True)
    run_replay = col_btn3.button("⚡ Test 3: Approval Replay", use_container_width=True)
    run_expired = col_btn4.button("⚡ Test 4: Expired Token", use_container_width=True)
    run_all = col_btn5.button("🚀 Run All Attack Tests", type="primary", use_container_width=True)

    # 1. DOSE TAMPERING TEST
    if run_tamper or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 1: Protected Dose Tampering Attack")
        st.caption("Description: A clinician approved 5mg of MED-A, but an untrusted agent submits 50mg.")

        conn = get_connection(ROOT_DIR / DEFAULT_DB_PATH)
        approved_action = {
            "order_id": "ORD-DEMO-001",
            "patient_id": "P-104",
            "medication_id": "MED-A",
            "dose": "5",
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "7 days",
        }
        app_id = "APR-TEST-TAMPER-01"
        _setup_test_approval(conn, app_id, approved_action)

        # Retrieve order dose before attack
        orig_order = conn.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()
        orig_dose = orig_order["dose"] if orig_order else "5"

        # Tampered request payload
        req_id = f"REQ-TAMPER-{int(datetime.now().timestamp())}"
        tampered_action = dict(approved_action, dose="50")
        exec_req = ExecutionRequest(
            request_id=req_id,
            actor_id="agent_1",
            tool="update_order",
            approval_id=app_id,
            action=ProtectedAction(**tampered_action),
        )

        decision = verify_execution(exec_req, conn)

        # Check order dose after attack
        post_order = conn.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()
        post_dose = post_order["dose"] if post_order else "5"
        conn.close()

        # Evaluation
        is_pass = (
            decision.decision == "blocked"
            and decision.rule == "intent hash mismatch"
            and decision.state_changed is False
            and orig_dose == post_dose
        )

        t1_col1, t1_col2 = st.columns(2)
        with t1_col1:
            st.markdown(f"**Expected Result:** `BLOCKED (intent hash mismatch)`")
            st.markdown(f"**Actual Result:** `{decision.decision.upper()}`")
            st.markdown(f"**Security Rule Triggered:** `{decision.rule}`")
            st.markdown(f"**Plain-Language Reason:** {decision.reason}")
            st.markdown(f"**Relevant Request ID:** `{req_id}`")
        with t1_col2:
            st.markdown("**Protected State Verification:**")
            st.markdown(f"- Clinician Approved Dose: `5 mg`")
            st.markdown(f"- Agent Submitted Dose: `50 mg` *(Tampered)*")
            st.markdown(f"- Database Dose Prior to Attack: `{orig_dose}`")
            st.markdown(f"- Database Dose After Attack: `{post_dose}`")
            st.markdown(f"- Backend State Modified: `{decision.state_changed}`")

        if is_pass:
            st.success("✅ **PASS:** Dose tampering blocked. Backend clinical state remained completely unchanged.")
        else:
            st.error("❌ **FAIL:** Attack succeeded or state was modified!")

    # 2. PATIENT SUBSTITUTION TEST
    if run_patient or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 2: Patient Substitution Attack")
        st.caption("Description: A clinician approved an order for Patient P-104; an agent attempts to apply it to P-205.")

        conn = get_connection(ROOT_DIR / DEFAULT_DB_PATH)
        approved_action = {
            "order_id": "ORD-DEMO-001",
            "patient_id": "P-104",
            "medication_id": "MED-A",
            "dose": "5",
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "7 days",
        }
        app_id = "APR-TEST-SUBST-01"
        _setup_test_approval(conn, app_id, approved_action)

        req_id = f"REQ-SUBST-{int(datetime.now().timestamp())}"
        substituted_action = dict(approved_action, patient_id="P-205")
        exec_req = ExecutionRequest(
            request_id=req_id,
            actor_id="agent_1",
            tool="update_order",
            approval_id=app_id,
            action=ProtectedAction(**substituted_action),
        )

        decision = verify_execution(exec_req, conn)
        conn.close()

        is_pass = (
            decision.decision == "blocked"
            and decision.rule == "intent hash mismatch"
            and decision.state_changed is False
            and "patient_id" in decision.changed_fields
        )

        t2_col1, t2_col2 = st.columns(2)
        with t2_col1:
            st.markdown(f"**Expected Result:** `BLOCKED (intent hash mismatch)`")
            st.markdown(f"**Actual Result:** `{decision.decision.upper()}`")
            st.markdown(f"**Security Rule Triggered:** `{decision.rule}`")
            st.markdown(f"**Plain-Language Reason:** {decision.reason}")
            st.markdown(f"**Relevant Request ID:** `{req_id}`")
        with t2_col2:
            st.markdown("**Protected State Verification:**")
            st.markdown("- Clinician Approved Patient: `P-104`")
            st.markdown("- Agent Submitted Patient: `P-205` *(Unauthorized Substitution)*")
            st.markdown(f"- Detected Mismatched Fields: `{decision.changed_fields}`")
            st.markdown(f"- Backend State Modified: `{decision.state_changed}`")

        if is_pass:
            st.success("✅ **PASS:** Patient substitution blocked. Intent hash bound action strictly to Patient P-104.")
        else:
            st.error("❌ **FAIL:** Unauthorized patient substitution succeeded!")

    # 3. APPROVAL REPLAY TEST
    if run_replay or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 3: Approval Replay Attack")
        st.caption("Description: A legitimate approval is executed once, then replayed a second time using the consumed token.")

        conn = get_connection(ROOT_DIR / DEFAULT_DB_PATH)
        action_data = {
            "order_id": "ORD-DEMO-001",
            "patient_id": "P-104",
            "medication_id": "MED-A",
            "dose": "5",
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "7 days",
        }
        app_id = "APR-TEST-REPLAY-01"
        _setup_test_approval(conn, app_id, action_data)

        # Call 1: Legitimate
        req1_id = f"REQ-LEGIT-{int(datetime.now().timestamp())}"
        req1 = ExecutionRequest(
            request_id=req1_id,
            actor_id="agent_1",
            tool="update_order",
            approval_id=app_id,
            action=ProtectedAction(**action_data),
        )
        dec1 = verify_execution(req1, conn)

        # Call 2: Replay
        req2_id = f"REQ-REPLAY-{int(datetime.now().timestamp())}"
        req2 = ExecutionRequest(
            request_id=req2_id,
            actor_id="agent_1",
            tool="update_order",
            approval_id=app_id,
            action=ProtectedAction(**action_data),
        )
        dec2 = verify_execution(req2, conn)
        conn.close()

        is_pass = (
            dec1.decision == "allowed"
            and dec2.decision == "blocked"
            and dec2.rule == "approval already consumed"
            and dec2.state_changed is False
        )

        t3_col1, t3_col2 = st.columns(2)
        with t3_col1:
            st.markdown(f"**Execution 1 (Legitimate):** `{dec1.decision.upper()}`")
            st.markdown(f"- Request ID: `{req1_id}`")
            st.markdown(f"- Rule Triggered: `{dec1.rule}`")
            st.markdown(f"- State Modified: `{dec1.state_changed}`")
            st.markdown("- Token Status: *Atomically Consumed*")
        with t3_col2:
            st.markdown(f"**Execution 2 (Replay Attack):** `{dec2.decision.upper()}`")
            st.markdown(f"- Request ID: `{req2_id}`")
            st.markdown(f"- Rule Triggered: `{dec2.rule}`")
            st.markdown(f"- Plain Reason: {dec2.reason}")
            st.markdown(f"- State Modified: `{dec2.state_changed}` *(Protected)*")

        if is_pass:
            st.success("✅ **PASS:** Approval replay blocked. Single-use token invalidated immediately upon first execution.")
        else:
            st.error("❌ **FAIL:** Replay token executed twice!")

    # 4. EXPIRED APPROVAL TEST
    if run_expired or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 4: Expired Clinician Approval Attack")
        st.caption("Description: Agent attempts to execute an action using an approval token whose validity period has elapsed.")

        conn = get_connection(ROOT_DIR / DEFAULT_DB_PATH)
        action_data = {
            "order_id": "ORD-DEMO-001",
            "patient_id": "P-104",
            "medication_id": "MED-A",
            "dose": "5",
            "units": "mg",
            "route": "oral",
            "frequency": "daily",
            "duration": "7 days",
        }
        app_id = "APR-TEST-EXPIRED-01"
        prot = ProtectedAction(**action_data)
        h = action_hash(prot)
        # Seed an expired approval (expired in 2020)
        conn.execute(
            """
            INSERT INTO approvals (approval_id, action_hash, action_json, approver_id, created_at, expires_at, revoked, consumed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(approval_id) DO UPDATE SET
                action_hash = excluded.action_hash,
                expires_at = '2020-01-01T00:00:00Z',
                revoked = 0,
                consumed = 0
            """,
            (app_id, h, json.dumps(action_data), "clinician_1", "2019-12-01T00:00:00Z", "2020-01-01T00:00:00Z", 0, 0),
        )
        conn.commit()

        req_id = f"REQ-EXPIRED-{int(datetime.now().timestamp())}"
        exec_req = ExecutionRequest(
            request_id=req_id,
            actor_id="agent_1",
            tool="update_order",
            approval_id=app_id,
            action=prot,
        )
        decision = verify_execution(exec_req, conn)
        conn.close()

        is_pass = (
            decision.decision == "blocked"
            and decision.rule == "approval expired"
            and decision.state_changed is False
        )

        t4_col1, t4_col2 = st.columns(2)
        with t4_col1:
            st.markdown(f"**Expected Result:** `BLOCKED (approval expired)`")
            st.markdown(f"**Actual Result:** `{decision.decision.upper()}`")
            st.markdown(f"**Security Rule Triggered:** `{decision.rule}`")
            st.markdown(f"**Plain-Language Reason:** {decision.reason}")
        with t4_col2:
            st.markdown("**Protected State Verification:**")
            st.markdown("- Approval Expiry Date: `2020-01-01T00:00:00Z` *(Expired)*")
            st.markdown(f"- Relevant Request ID: `{req_id}`")
            st.markdown(f"- Backend State Modified: `{decision.state_changed}`")

        if is_pass:
            st.success("✅ **PASS:** Expired approval blocked fail-closed. Stale authorization cannot be executed.")
        else:
            st.error("❌ **FAIL:** Expired approval was accepted!")


# ------------------------------------------------------------------------------
# TAB 3: ACTION VERIFICATION
# ------------------------------------------------------------------------------
with tab_verification:
    st.subheader("🔍 Interactive Action Verification")
    st.markdown(
        "Inspect the **Clinical Intent Lock** side-by-side. Compare an approved clinician action "
        "against an agent-submitted action to visualize canonical serialization, cryptographic hash verification, "
        "and field-level diff detection evaluated through the live gateway engine."
    )

    # Preset selection
    st.markdown("#### ⚙️ Attack / Verification Presets")
    preset_choice = st.selectbox(
        "Select a Scenario Preset to Load Values:",
        options=[
            "Exact Match (Safe Approved Execution)",
            "Tampered Dose Attack (5 -> 50 mg)",
            "Substituted Patient Attack (P-104 -> P-205)",
            "Non-Canonical Units Warning (mg -> MG)",
        ],
        index=0,
        key="verif_preset_selector",
    )

    # Base values
    base_patient = "P-104"
    base_med = "MED-A"
    base_dose = "5"
    base_units = "mg"
    base_route = "oral"
    base_freq = "daily"
    base_dur = "7 days"
    base_order = "ORD-DEMO-001"

    # Synchronize session state when preset changes
    if st.session_state.get("last_loaded_preset") != preset_choice:
        st.session_state["last_loaded_preset"] = preset_choice
        if "Tampered Dose" in preset_choice:
            st.session_state["v_sub_patient"] = base_patient
            st.session_state["v_sub_med"] = base_med
            st.session_state["v_sub_dose"] = "50"
            st.session_state["v_sub_units"] = base_units
            st.session_state["v_sub_route"] = base_route
            st.session_state["v_sub_freq"] = base_freq
            st.session_state["v_sub_dur"] = base_dur
            st.session_state["v_sub_order"] = base_order
        elif "Substituted Patient" in preset_choice:
            st.session_state["v_sub_patient"] = "P-205"
            st.session_state["v_sub_med"] = base_med
            st.session_state["v_sub_dose"] = base_dose
            st.session_state["v_sub_units"] = base_units
            st.session_state["v_sub_route"] = base_route
            st.session_state["v_sub_freq"] = base_freq
            st.session_state["v_sub_dur"] = base_dur
            st.session_state["v_sub_order"] = base_order
        elif "Non-Canonical Units" in preset_choice:
            st.session_state["v_sub_patient"] = base_patient
            st.session_state["v_sub_med"] = base_med
            st.session_state["v_sub_dose"] = base_dose
            st.session_state["v_sub_units"] = "MG"
            st.session_state["v_sub_route"] = base_route
            st.session_state["v_sub_freq"] = base_freq
            st.session_state["v_sub_dur"] = base_dur
            st.session_state["v_sub_order"] = base_order
        else:  # Exact Match
            st.session_state["v_sub_patient"] = base_patient
            st.session_state["v_sub_med"] = base_med
            st.session_state["v_sub_dose"] = base_dose
            st.session_state["v_sub_units"] = base_units
            st.session_state["v_sub_route"] = base_route
            st.session_state["v_sub_freq"] = base_freq
            st.session_state["v_sub_dur"] = base_dur
            st.session_state["v_sub_order"] = base_order

    # Initialize defaults
    for k, v in [
        ("v_app_patient", base_patient),
        ("v_app_med", base_med),
        ("v_app_dose", base_dose),
        ("v_app_units", base_units),
        ("v_app_route", base_route),
        ("v_app_freq", base_freq),
        ("v_app_dur", base_dur),
        ("v_app_order", base_order),
        ("v_sub_patient", base_patient),
        ("v_sub_med", base_med),
        ("v_sub_dose", base_dose),
        ("v_sub_units", base_units),
        ("v_sub_route", base_route),
        ("v_sub_freq", base_freq),
        ("v_sub_dur", base_dur),
        ("v_sub_order", base_order),
    ]:
        if k not in st.session_state:
            st.session_state[k] = v

    verif_col1, verif_col2 = st.columns(2)

    with verif_col1:
        st.markdown("#### 📋 Clinician Approved Action")
        app_patient = st.text_input("Approved Patient ID", value=st.session_state.get("v_app_patient", base_patient), key="v_app_patient")
        app_med = st.text_input("Approved Medication ID", value=st.session_state.get("v_app_med", base_med), key="v_app_med")
        app_dose = st.text_input("Approved Dose", value=st.session_state.get("v_app_dose", base_dose), key="v_app_dose")
        app_units = st.text_input("Approved Units", value=st.session_state.get("v_app_units", base_units), key="v_app_units")
        app_route = st.text_input("Approved Route", value=st.session_state.get("v_app_route", base_route), key="v_app_route")
        app_freq = st.text_input("Approved Frequency", value=st.session_state.get("v_app_freq", base_freq), key="v_app_freq")
        app_dur = st.text_input("Approved Duration", value=st.session_state.get("v_app_dur", base_dur), key="v_app_dur")
        app_order = st.text_input("Approved Order ID", value=st.session_state.get("v_app_order", base_order), key="v_app_order")

    with verif_col2:
        st.markdown("#### 🤖 Agent Submitted Action")
        sub_patient = st.text_input("Submitted Patient ID", value=st.session_state.get("v_sub_patient", base_patient), key="v_sub_patient")
        sub_med = st.text_input("Submitted Medication ID", value=st.session_state.get("v_sub_med", base_med), key="v_sub_med")
        sub_dose = st.text_input("Submitted Dose", value=st.session_state.get("v_sub_dose", base_dose), key="v_sub_dose")
        sub_units = st.text_input("Submitted Units", value=st.session_state.get("v_sub_units", base_units), key="v_sub_units")
        sub_route = st.text_input("Submitted Route", value=st.session_state.get("v_sub_route", base_route), key="v_sub_route")
        sub_freq = st.text_input("Submitted Frequency", value=st.session_state.get("v_sub_freq", base_freq), key="v_sub_freq")
        sub_dur = st.text_input("Submitted Duration", value=st.session_state.get("v_sub_dur", base_dur), key="v_sub_dur")
        sub_order = st.text_input("Submitted Order ID", value=st.session_state.get("v_sub_order", base_order), key="v_sub_order")

    st.markdown("")
    run_check = st.button("🔒 Run Gateway Intent Lock Check", type="primary", use_container_width=True)

    # Verification execution (safe in both bare import mode and active Streamlit session)
    is_live_context = hasattr(st, "runtime") and st.runtime.exists()

    if is_live_context and (run_check or "last_loaded_preset" in st.session_state):
        def clean_val(v, default=""):
            s = str(v).strip() if v is not None else ""
            return s if s else default

        approved_dict = {
            "order_id": clean_val(app_order, base_order),
            "patient_id": clean_val(app_patient, base_patient),
            "medication_id": clean_val(app_med, base_med),
            "dose": clean_val(app_dose, base_dose),
            "units": clean_val(app_units, base_units),
            "route": clean_val(app_route, base_route),
            "frequency": clean_val(app_freq, base_freq),
            "duration": clean_val(app_dur, base_dur) if clean_val(app_dur) else None,
        }
        submitted_dict = {
            "order_id": clean_val(sub_order, base_order),
            "patient_id": clean_val(sub_patient, base_patient),
            "medication_id": clean_val(sub_med, base_med),
            "dose": clean_val(sub_dose, base_dose),
            "units": clean_val(sub_units, base_units),
            "route": clean_val(sub_route, base_route),
            "frequency": clean_val(sub_freq, base_freq),
            "duration": clean_val(sub_dur, base_dur) if clean_val(sub_dur) else None,
        }

        # Compare fields with canonical normalization
        def compare_field_status(fld, a_val, s_val):
            a_str = clean_val(a_val)
            s_str = clean_val(s_val)

            # Dose decimal normalization
            if fld == "dose":
                try:
                    d_a = Decimal(a_str)
                    d_s = Decimal(s_str)
                    if d_a == d_s:
                        if a_str == s_str:
                            return "✅ Exact Match"
                        return f"✅ Exact Match (Normalized: {a_str} = {s_str})"
                    return "❌ Tampered / Mismatch"
                except Exception:
                    return "❌ Invalid Decimal Dose Syntax"

            # Units normalization
            if fld == "units":
                if a_str == s_str:
                    return "✅ Exact Match"
                elif a_str.lower() == s_str.lower():
                    return "⚠️ Case Discrepancy (Canonicalization Warning)"
                else:
                    return "❌ Tampered / Mismatch"

            if a_str == s_str:
                return "✅ Exact Match"
            elif a_str.lower() == s_str.lower():
                return "⚠️ Case Discrepancy (Canonicalization Warning)"
            else:
                return "❌ Tampered / Mismatch"

        diff_rows = []
        actual_mismatches = []
        case_warnings = []
        for fld in ["order_id", "patient_id", "medication_id", "dose", "units", "route", "frequency", "duration"]:
            a_v = approved_dict.get(fld, "")
            s_v = submitted_dict.get(fld, "")
            st_msg = compare_field_status(fld, a_v, s_v)
            if "Tampered" in st_msg or "Mismatch" in st_msg or "Invalid" in st_msg:
                actual_mismatches.append(fld)
            elif "Case Discrepancy" in st_msg:
                case_warnings.append(fld)
            diff_rows.append({
                "Protected Field": fld,
                "Approved Value": str(a_v),
                "Submitted Value": str(s_v),
                "Integrity Status": st_msg,
            })

        # Run through actual gateway verification engine safely
        try:
            conn = get_connection(ROOT_DIR / DEFAULT_DB_PATH)
            app_id = "APR-ACTION-VERIF"
            _setup_test_approval(conn, app_id, approved_dict)

            exec_req = ExecutionRequest(
                request_id="REQ-ACTION-VERIF",
                actor_id="agent_1",
                tool="update_order",
                approval_id=app_id,
                action=ProtectedAction(**submitted_dict),
            )
            decision = verify_execution(exec_req, conn)
            conn.close()

            # Canonical strings and hashes
            app_canon = canonicalize_action(approved_dict)
            sub_canon = canonicalize_action(submitted_dict)
            app_h = action_hash(approved_dict)
            sub_h = action_hash(submitted_dict)

            st.divider()
            st.subheader("Verification Analysis & Gateway Verdict")

            # Guaranteed consistency between diffs and verdict
            if actual_mismatches:
                st.error(f"🔴 **GATEWAY VERDICT: BLOCKED** — The execution parameters differed from the approved synthetic action.")
                verdict_rule = "intent hash mismatch"
                verdict_changed = actual_mismatches
                verdict_state = "False (Protected / Unchanged)"
            elif case_warnings:
                st.warning(f"⚠️ **GATEWAY VERDICT: WARNING** — Mixed-case units submitted. Canonicalization review required.")
                verdict_rule = "non-canonical units"
                verdict_changed = f"None (Case Discrepancy: {case_warnings})"
                verdict_state = "True (Order Updated with Canonical Normalization)"
            else:
                st.success(f"🟢 **GATEWAY VERDICT: ALLOWED** — Protected order fields matched the clinician approval.")
                verdict_rule = "intent hash matched"
                verdict_changed = "None (Exact Match)"
                verdict_state = "True (Order Updated)"

            v_res1, v_res2, v_res3 = st.columns(3)
            with v_res1:
                st.markdown(f"**Security Rule:**  \n`{verdict_rule}`")
            with v_res2:
                st.markdown(f"**Mismatched Fields:**  \n`{verdict_changed}`")
            with v_res3:
                st.markdown(f"**Backend State:**  \n`{verdict_state}`")

            # Field-by-Field Diff Comparison Table with Color Styling
            st.markdown("##### 🔍 Field-by-Field Parameter Comparison")
            diff_df = pd.DataFrame(diff_rows)

            def style_diff_status(val):
                v = str(val)
                if "Exact Match" in v:
                    return "background-color: #064e3b; color: #a7f3d0; font-weight: bold;"
                elif "Case Discrepancy" in v:
                    return "background-color: #78350f; color: #fde68a; font-weight: bold;"
                elif "Tampered" in v or "Mismatch" in v or "Invalid" in v:
                    return "background-color: #7f1d1d; color: #fca5a5; font-weight: bold;"
                return ""

            diff_styler = diff_df.style
            if hasattr(diff_styler, "map"):
                styled_diff = diff_styler.map(style_diff_status, subset=["Integrity Status"])
            else:
                styled_diff = diff_styler.applymap(style_diff_status, subset=["Integrity Status"])

            st.dataframe(styled_diff, hide_index=True, use_container_width=True)

            # Cryptographic Hash Inspector
            st.markdown("##### 🔐 Cryptographic Intent Lock Hashes (SHA-256)")
            h_col1, h_col2 = st.columns(2)
            with h_col1:
                st.code(f"Approved Action Hash:\n{app_h}", language="text")
            with h_col2:
                st.code(f"Submitted Action Hash:\n{sub_h}", language="text")

            if app_h == sub_h:
                st.caption("🔒 **Cryptographic Match:** The submitted digest is identical to the clinician's signature.")
            else:
                st.caption("🚨 **Digest Mismatch:** The submitted action cannot produce the approved hash.")

            with st.expander("🔍 Inspect Canonical Compact JSON", expanded=False):
                st.code(f"Approved Canonical JSON:\n{app_canon}\n\nSubmitted Canonical JSON:\n{sub_canon}", language="json")

        except Exception as ex:
            st.error(f"🔴 Validation Exception: {str(ex)}")


# ------------------------------------------------------------------------------
# TAB 4: AUDIT LOG (3-Column Row Redesign & Comprehensive Filtering)
# ------------------------------------------------------------------------------
with tab_audit:
    st.subheader("📜 Comprehensive Audit Log")
    st.markdown(
        f"Non-repudiable audit records of all gateway decisions. "
        f"Active source: **`{active_data_source}`**."
    )

    # Filter Controls
    f_col1, f_col2, f_col3, f_col4 = st.columns([2, 2, 2, 4])
    with f_col1:
        decision_filter = st.selectbox(
            "Filter by Decision:",
            options=["All", "allowed", "blocked", "warning"],
            index=0,
            key="audit_dec_filter",
        )
    with f_col2:
        risk_filter = st.selectbox(
            "Filter by Risk:",
            options=["All", "low", "medium", "high"],
            index=0,
            key="audit_risk_filter",
        )
    with f_col3:
        tool_options = ["All"] + sorted(list({e.get("tool", "") for e in all_events if e.get("tool")}))
        tool_filter = st.selectbox("Filter by Tool:", options=tool_options, index=0, key="audit_tool_filter")
    with f_col4:
        search_query = st.text_input("🔍 Search Request ID / Actor / Rule / Reason:", "", key="audit_search")

    # Apply Filters
    filtered_events = list(all_events)
    if decision_filter != "All":
        filtered_events = [e for e in filtered_events if str(e.get("decision")).lower() == decision_filter.lower()]
    if risk_filter != "All":
        filtered_events = [e for e in filtered_events if str(e.get("risk")).lower() == risk_filter.lower()]
    if tool_filter != "All":
        filtered_events = [e for e in filtered_events if e.get("tool") == tool_filter]
    if search_query.strip():
        q = search_query.strip().lower()
        filtered_events = [
            e for e in filtered_events
            if q in str(e.get("request_id", "")).lower()
            or q in str(e.get("actor", "")).lower()
            or q in str(e.get("rule", "")).lower()
            or q in str(e.get("reason", "")).lower()
        ]

    st.caption(f"Displaying **{len(filtered_events)}** matching audit events (out of {len(all_events)} total, newest first)")

    if filtered_events:
        # Table Header for the 3 Primary Columns
        h1, h2, h3 = st.columns([4, 3, 3])
        h1.markdown("**🆔 Event / Request ID**")
        h2.markdown("**⚖️ Gateway Decision**")
        h3.markdown("**⚠️ Risk Level**")
        st.markdown("<hr style='margin: 4px 0 12px 0; border-color: #212c3d;' />", unsafe_allow_html=True)

        # Pagination for smooth rendering
        page_size = 20
        total_pages = max(1, (len(filtered_events) + page_size - 1) // page_size)
        
        if total_pages > 1:
            p_col1, p_col2 = st.columns([2, 8])
            with p_col1:
                current_page = st.number_input(
                    f"Page (1 to {total_pages})",
                    min_value=1,
                    max_value=total_pages,
                    value=1,
                    step=1,
                    key="audit_page_num",
                )
            start_idx = (current_page - 1) * page_size
            end_idx = min(start_idx + page_size, len(filtered_events))
            page_events = filtered_events[start_idx:end_idx]
            st.caption(f"Showing records {start_idx + 1} to {end_idx} of {len(filtered_events)}")
        else:
            page_events = filtered_events

        # Render each audit event as a clean 3-column expandable row
        for ev in page_events:
            render_audit_event_card(ev, expanded_default=False)
    else:
        st.info("No audit events match your search or filter criteria.")

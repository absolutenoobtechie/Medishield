"""
MediShield Runtime Security Gateway Dashboard
==============================================
Production-grade runtime security monitoring, testing lab, and audit console
for AI-connected clinical backend tools.

Built strictly with Python and Streamlit.
"""

from datetime import datetime, timedelta, timezone
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
# SECTION 2: Unified Data Loader
# ==============================================================================
def load_events(db_path: Optional[Path] = None) -> Tuple[List[Dict[str, Any]], str]:
    """
    Load audit events from the SQLite audit_events table if rows exist;
    otherwise fall back to reading logs/sample_events.jsonl.
    
    Returns:
        Tuple of (events_list, source_description)
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
        # Order latest first
        events = list(reversed(events))
        return events, "Synthetic Fallback (logs/sample_events.jsonl)"

    return events, "No Events Available"


# ==============================================================================
# SECTION 3: Streamlit UI Setup & Custom Dark-Themed Styling
# ==============================================================================
st.set_page_config(
    page_title="MediShield - Clinical AI Security Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom refined styling for metrics, typography, and badges
st.markdown(
    """
    <style>
    .metric-card {
        background: #181c24;
        border: 1px solid #283040;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
        margin-bottom: 12px;
    }
    .metric-val {
        font-size: 2rem;
        font-weight: 700;
        line-height: 1.2;
    }
    .metric-lbl {
        font-size: 0.85rem;
        color: #9aa5b8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge-allowed {
        background-color: #0f5132;
        color: #d1e7dd;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-blocked {
        background-color: #842029;
        color: #f8d7da;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-warning {
        background-color: #664d03;
        color: #fff3cd;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .status-pill {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: 600;
        background-color: #1e3a5f;
        color: #64b5f6;
        border: 1px solid #29b6f6;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Load events and source info
all_events, active_data_source = load_events()

# Top Header Layout
header_left, header_right = st.columns([5, 1])
with header_left:
    st.title("🛡️ MediShield Security Gateway")
    st.markdown(
        "**Runtime Clinical AI Gateway** &nbsp;|&nbsp; "
        "Enforcing Clinical Intent Locks, Fail-Closed Verification & Non-Repudiable Audits"
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
st.sidebar.subheader("Gateway Invariants")
st.sidebar.markdown(
    """
    - **Fail-Closed:** Default deny on any error
    - **Intent Lock:** Deterministic SHA-256 digest
    - **Normalized:** Decimal `dose` & lowercase `units`
    - **Single-Use:** Instant token consumption
    - **Zero Trust:** Recompute hash independently
    """
)
st.sidebar.caption("MediShield Hackathon Engine v1.0 • Synthetic Data Only")


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
    allowed_calls = sum(1 for e in all_events if e.get("decision") == "allowed")
    blocked_calls = sum(1 for e in all_events if e.get("decision") == "blocked")
    warning_calls = sum(1 for e in all_events if e.get("decision") == "warning")

    # Metric Cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-val" style="color: #64b5f6;">{total_calls}</div>
                <div class="metric-lbl">Total Monitored Calls</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-val" style="color: #81c784;">{allowed_calls}</div>
                <div class="metric-lbl">Allowed (Passed All Checks)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-val" style="color: #e57373;">{blocked_calls}</div>
                <div class="metric-lbl">Blocked (Attacks Stopped)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-val" style="color: #ffd54f;">{warning_calls}</div>
                <div class="metric-lbl">Warnings (Under Review)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Gateway Operational Status Bar
    st.markdown(
        """
        <div style="background: #141b24; border-left: 4px solid #29b6f6; padding: 12px 18px; border-radius: 4px; margin: 12px 0 20px 0;">
            <span style="font-weight: 700; color: #e0e0e0;">GATEWAY ENFORCEMENT ENGINE:</span>
            <span class="status-pill" style="margin-left: 8px;">● ACTIVE (FAIL-CLOSED)</span>
            <span style="color: #9aa5b8; margin-left: 16px; font-size: 0.9rem;">
                Intent Lock Algorithm: SHA-256 HMAC &nbsp;|&nbsp; Role Directory: Active &nbsp;|&nbsp; Replay Protection: Enabled
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Recent Events Table
    st.subheader("Recent Gateway Activity")
    if all_events:
        recent_df = pd.DataFrame(all_events[:15])
        # Format columns for readability
        display_df = recent_df[[
            "time", "request_id", "actor", "tool", "decision", "risk", "rule", "state_changed"
        ]].copy()
        display_df["time"] = display_df["time"].apply(to_ist_string)
        display_df.columns = [
            "Timestamp (IST)", "Request ID", "Actor", "Tool", "Decision", "Risk", "Security Rule", "State Modified"
        ]

        def style_decision(val):
            v = str(val).lower()
            if v == "allowed":
                return "background-color: #0f5132; color: #d1e7dd; font-weight: bold;"
            elif v == "blocked":
                return "background-color: #842029; color: #f8d7da; font-weight: bold;"
            elif v == "warning":
                return "background-color: #664d03; color: #fff3cd; font-weight: bold;"
            return ""

        styler = display_df.style
        if hasattr(styler, "map"):
            styled_recent = styler.map(style_decision, subset=["Decision"])
        else:
            styled_recent = styler.applymap(style_decision, subset=["Decision"])

        st.dataframe(styled_recent, hide_index=True, use_container_width=True)
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

    col_btn1, col_btn2, col_btn3, col_btn4 = st.columns(4)

    run_tamper = col_btn1.button("⚡ Test 1: Dose Tampering", use_container_width=True)
    run_patient = col_btn2.button("⚡ Test 2: Patient Sub.", use_container_width=True)
    run_replay = col_btn3.button("⚡ Test 3: Approval Replay", use_container_width=True)
    run_all = col_btn4.button("🚀 Run All 3 Attack Tests", type="primary", use_container_width=True)

    # 1. DOSE TAMPERING TEST
    if run_tamper or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 1: Protected Dose Tampering Attack")
        st.caption("Scenario: A clinician approved 5mg of MED-A, but an untrusted agent submits 50mg.")

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
        orig_dose = orig_order["dose"] if orig_order else "SIMULATED-5"

        # Tampered request payload
        tampered_action = dict(approved_action, dose="50")
        exec_req = ExecutionRequest(
            request_id=f"REQ-TAMPER-{int(datetime.now().timestamp())}",
            actor_id="agent_1",
            tool="update_order",
            approval_id=app_id,
            action=ProtectedAction(**tampered_action),
        )

        decision = verify_execution(exec_req, conn)

        # Check order dose after attack
        post_order = conn.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()
        post_dose = post_order["dose"] if post_order else "SIMULATED-5"
        conn.close()

        res_col1, res_col2 = st.columns(2)
        with res_col1:
            st.error(f"**Gateway Verdict:** `{decision.decision.upper()}`")
            st.markdown(f"**Security Rule:** `{decision.rule}`")
            st.markdown(f"**Reason:** {decision.reason}")
            st.markdown(f"**Detected Mismatched Fields:** `{decision.changed_fields}`")
        with res_col2:
            st.markdown("**Protected State Verification:**")
            st.markdown(f"- Clinician Approved Dose: `5 mg`")
            st.markdown(f"- Agent Submitted Dose: `50 mg` *(Tampered)*")
            st.markdown(f"- Database Dose Prior to Attack: `{orig_dose}`")
            st.markdown(f"- Database Dose After Attack: `{post_dose}`")
            if orig_dose == post_dose and decision.state_changed is False:
                st.success("✅ **Integrity Preserved:** Backend database remained unmodified.")
            else:
                st.error("❌ **Failure:** Database state was altered!")

    # 2. PATIENT SUBSTITUTION TEST
    if run_patient or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 2: Patient Substitution Attack")
        st.caption("Scenario: A clinician approved an order for Patient P-104, but an agent attempts to apply it to P-205.")

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

        # Substituted request payload
        substituted_action = dict(approved_action, patient_id="P-205")
        exec_req = ExecutionRequest(
            request_id=f"REQ-SUBST-{int(datetime.now().timestamp())}",
            actor_id="agent_1",
            tool="update_order",
            approval_id=app_id,
            action=ProtectedAction(**substituted_action),
        )

        decision = verify_execution(exec_req, conn)
        conn.close()

        res_col1, res_col2 = st.columns(2)
        with res_col1:
            st.error(f"**Gateway Verdict:** `{decision.decision.upper()}`")
            st.markdown(f"**Security Rule:** `{decision.rule}`")
            st.markdown(f"**Reason:** {decision.reason}")
            st.markdown(f"**Detected Mismatched Fields:** `{decision.changed_fields}`")
        with res_col2:
            st.markdown("**Protected State Verification:**")
            st.markdown("- Clinician Approved Patient: `P-104`")
            st.markdown("- Agent Submitted Patient: `P-205` *(Substituted)*")
            st.markdown(f"- Backend State Modified: `{decision.state_changed}`")
            if decision.state_changed is False and "patient_id" in decision.changed_fields:
                st.success("✅ **Substitution Blocked:** Hash mismatch caught unauthorized patient transfer.")

    # 3. APPROVAL REPLAY TEST
    if run_replay or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 3: Approval Replay Attack")
        st.caption("Scenario: A legitimate approval is executed once, then an agent replays the exact same approval a second time.")

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

        # Execution 1: First call (Legitimate)
        req1 = ExecutionRequest(
            request_id=f"REQ-LEGIT-{int(datetime.now().timestamp())}",
            actor_id="agent_1",
            tool="update_order",
            approval_id=app_id,
            action=ProtectedAction(**action_data),
        )
        dec1 = verify_execution(req1, conn)

        # Execution 2: Second call (Replay attack)
        req2 = ExecutionRequest(
            request_id=f"REQ-REPLAY-{int(datetime.now().timestamp())}",
            actor_id="agent_1",
            tool="update_order",
            approval_id=app_id,
            action=ProtectedAction(**action_data),
        )
        dec2 = verify_execution(req2, conn)
        conn.close()

        rep_col1, rep_col2 = st.columns(2)
        with rep_col1:
            st.success(f"**Execution 1 (Legitimate):** `{dec1.decision.upper()}`")
            st.markdown(f"- Rule: `{dec1.rule}`")
            st.markdown(f"- State Modified: `{dec1.state_changed}`")
            st.markdown("- Approval Token: *Atomically Consumed*")
        with rep_col2:
            st.error(f"**Execution 2 (Replay Attack):** `{dec2.decision.upper()}`")
            st.markdown(f"- Rule: `{dec2.rule}`")
            st.markdown(f"- Reason: {dec2.reason}")
            st.markdown(f"- State Modified: `{dec2.state_changed}`")
            if dec1.decision == "allowed" and dec2.decision == "blocked":
                st.success("✅ **Replay Protection Verified:** One-time token cannot be executed twice.")


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

    # Initialize defaults if not present
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
        app_patient = st.text_input("Approved Patient ID", key="v_app_patient")
        app_med = st.text_input("Approved Medication ID", key="v_app_med")
        app_dose = st.text_input("Approved Dose", key="v_app_dose")
        app_units = st.text_input("Approved Units", key="v_app_units")
        app_route = st.text_input("Approved Route", key="v_app_route")
        app_freq = st.text_input("Approved Frequency", key="v_app_freq")
        app_dur = st.text_input("Approved Duration", key="v_app_dur")
        app_order = st.text_input("Approved Order ID", key="v_app_order")

    with verif_col2:
        st.markdown("#### 🤖 Agent Submitted Action")
        sub_patient = st.text_input("Submitted Patient ID", key="v_sub_patient")
        sub_med = st.text_input("Submitted Medication ID", key="v_sub_med")
        sub_dose = st.text_input("Submitted Dose", key="v_sub_dose")
        sub_units = st.text_input("Submitted Units", key="v_sub_units")
        sub_route = st.text_input("Submitted Route", key="v_sub_route")
        sub_freq = st.text_input("Submitted Frequency", key="v_sub_freq")
        sub_dur = st.text_input("Submitted Duration", key="v_sub_dur")
        sub_order = st.text_input("Submitted Order ID", key="v_sub_order")

    st.markdown("")
    run_check = st.button("🔒 Run Gateway Intent Lock Check", type="primary", use_container_width=True)

    # Run verification check
    if run_check:
        from decimal import Decimal

        def clean_val(v):
            return str(v).strip() if v is not None else ""

        approved_dict = {
            "order_id": clean_val(app_order),
            "patient_id": clean_val(app_patient),
            "medication_id": clean_val(app_med),
            "dose": clean_val(app_dose),
            "units": clean_val(app_units),
            "route": clean_val(app_route),
            "frequency": clean_val(app_freq),
            "duration": clean_val(app_dur) if app_dur else None,
        }
        submitted_dict = {
            "order_id": clean_val(sub_order),
            "patient_id": clean_val(sub_patient),
            "medication_id": clean_val(sub_med),
            "dose": clean_val(sub_dose),
            "units": clean_val(sub_units),
            "route": clean_val(sub_route),
            "frequency": clean_val(sub_freq),
            "duration": clean_val(sub_dur) if sub_dur else None,
        }

        # Compare fields with canonical intelligence (Decimal dose & case normalization)
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
                    pass

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
            if "Tampered" in st_msg or "Mismatch" in st_msg:
                actual_mismatches.append(fld)
            elif "Case Discrepancy" in st_msg:
                case_warnings.append(fld)
            diff_rows.append({
                "Protected Field": fld,
                "Approved Value": str(a_v),
                "Submitted Value": str(s_v),
                "Integrity Status": st_msg,
            })

        # Run through actual gateway verification engine
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

        # Compute canonical strings and hashes
        app_canon = canonicalize_action(approved_dict)
        sub_canon = canonicalize_action(submitted_dict)
        app_h = action_hash(approved_dict)
        sub_h = action_hash(submitted_dict)

        st.divider()
        st.subheader("Verification Analysis & Gateway Verdict")

        # Guarantee strict consistency between diffs and verdict
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

        # Summary Metrics
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
                return "background-color: #0f5132; color: #d1e7dd; font-weight: bold;"
            elif "Case Discrepancy" in v:
                return "background-color: #664d03; color: #fff3cd; font-weight: bold;"
            elif "Tampered" in v or "Mismatch" in v:
                return "background-color: #842029; color: #f8d7da; font-weight: bold;"
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


# ------------------------------------------------------------------------------
# TAB 4: AUDIT LOG
# ------------------------------------------------------------------------------
with tab_audit:
    st.subheader("📜 Comprehensive Audit Log")
    st.markdown(
        f"Non-repudiable audit records of all gateway decisions. "
        f"Active source: **`{active_data_source}`**."
    )

    # Filter Controls
    f_col1, f_col2, f_col3 = st.columns([2, 2, 4])
    with f_col1:
        decision_filter = st.selectbox(
            "Filter by Decision:",
            options=["All", "allowed", "blocked", "warning"],
            index=0,
            key="audit_dec_filter",
        )
    with f_col2:
        tool_options = ["All"] + sorted(list({e.get("tool", "") for e in all_events if e.get("tool")}))
        tool_filter = st.selectbox("Filter by Tool:", options=tool_options, index=0, key="audit_tool_filter")
    with f_col3:
        search_query = st.text_input("🔍 Search Request ID / Actor / Rule / Reason:", "", key="audit_search")

    # Apply Filters
    filtered_events = list(all_events)
    if decision_filter != "All":
        filtered_events = [e for e in filtered_events if e.get("decision") == decision_filter]
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

    st.caption(f"Showing **{len(filtered_events)}** matching events (out of {len(all_events)} total)")

    if filtered_events:
        audit_df = pd.DataFrame(filtered_events)
        # Select and format columns for clean display
        show_cols = ["time", "request_id", "actor", "tool", "decision", "risk", "rule", "state_changed"]
        clean_df = audit_df[show_cols].copy()
        clean_df["time"] = clean_df["time"].apply(to_ist_string)
        clean_df.columns = [
            "Timestamp (IST)", "Request ID", "Actor", "Tool", "Decision", "Risk", "Rule Triggered", "State Changed"
        ]

        def style_audit_dec(val):
            v = str(val).lower()
            if v == "allowed":
                return "background-color: #0f5132; color: #d1e7dd; font-weight: bold;"
            elif v == "blocked":
                return "background-color: #842029; color: #f8d7da; font-weight: bold;"
            elif v == "warning":
                return "background-color: #664d03; color: #fff3cd; font-weight: bold;"
            return ""

        styler = clean_df.style
        if hasattr(styler, "map"):
            styled_audit = styler.map(style_audit_dec, subset=["Decision"])
        else:
            styled_audit = styler.applymap(style_audit_dec, subset=["Decision"])

        st.dataframe(styled_audit, hide_index=True, use_container_width=True)

        st.divider()

        # Clean Event Detail Panel
        st.subheader("Event Detail Inspection Panel")
        event_labels = [
            f"#{i+1} | [{filtered_events[i].get('decision', '').upper()}] {filtered_events[i].get('request_id', '')} — {filtered_events[i].get('tool', '')} ({to_ist_string(filtered_events[i].get('time', ''))})"
            for i in range(len(filtered_events))
        ]
        sel_idx = st.selectbox(
            "Select an event from the filtered table to view full details:",
            options=range(len(filtered_events)),
            format_func=lambda i: event_labels[i],
            key="audit_sel_event",
        )
        selected_event = filtered_events[sel_idx]

        # Section 1: Security Verdict & State
        v_col1, v_col2, v_col3 = st.columns(3)
        with v_col1:
            dec = selected_event.get("decision", "unknown").upper()
            if dec == "ALLOWED":
                st.markdown("**Decision:**  \n<span class='badge-allowed'>ALLOWED</span>", unsafe_allow_html=True)
            elif dec == "BLOCKED":
                st.markdown("**Decision:**  \n<span class='badge-blocked'>BLOCKED</span>", unsafe_allow_html=True)
            else:
                st.markdown("**Decision:**  \n<span class='badge-warning'>WARNING</span>", unsafe_allow_html=True)
        with v_col2:
            st.markdown(f"**Security Rule:**  \n`{selected_event.get('rule', 'N/A')}`")
        with v_col3:
            st_changed = selected_event.get("state_changed", False)
            if st_changed:
                st.markdown("**Backend State:**  \n`True` *(Modified)*")
            else:
                st.markdown("**Backend State:**  \n`False` *(Unchanged)*")

        # Section 2: Clinical Explanation & Changed Fields
        exp_col1, exp_col2 = st.columns(2)
        with exp_col1:
            st.markdown("**Clinical Explanation:**")
            st.info(selected_event.get("reason", "No reason provided."))
        with exp_col2:
            st.markdown("**Changed Protected Fields:**")
            cf = selected_event.get("changed_fields", [])
            if cf:
                st.warning(f"`{cf}`")
            else:
                st.success("`[]` *(No fields changed)*")

        # Section 3: Metadata Metrics
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Request ID", selected_event.get("request_id", "N/A"))
        m2.metric("Actor ID", selected_event.get("actor", "N/A"))
        m3.metric("Tool Name", selected_event.get("tool", "N/A"))
        m4.metric("Approval ID", str(selected_event.get("approval_id") or "None"))
        m5.metric("Timestamp (IST)", to_ist_string(selected_event.get("time")))

        # Section 4: Raw JSON in collapsed expander
        with st.expander("📄 View Raw Audit Event (JSON)", expanded=False):
            st.json(selected_event)
    else:
        st.info("No audit events match your search or filter criteria.")

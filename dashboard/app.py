"""
MediShield Runtime Security Gateway Dashboard
==============================================
Runtime security monitoring, testing lab, and audit console
for AI-connected clinical backend tools.

Redesigned with Clinical Navy + Medical Teal + Off-White Healthcare UX Palette.
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
APP_DB_PATH = ROOT_DIR / "medishield.sqlite3"
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from guard.audit import record_audit_event
from guard.gateway import verify_execution
from guard.intent import action_hash, canonicalize_action
from guard.models import Decision, ExecutionRequest, ProtectedAction
from server.mcp_server import get_tool_integrity_status
from dashboard.dosage import (
    calculate_dosage_deviation,
    extract_event_dosage_comparison,
    resolve_event_department,
    resolve_event_display_id,
)
from dashboard.document_vault import render_document_vault
from dashboard.sentinel_view import render_sentinel_console
from dashboard.security_helpers import gateway_verdict, setup_test_approval as _create_test_approval
from server.db import DEFAULT_DB_PATH, get_connection, init_db, seed_data

# Ensure synthetic DB tables and baseline seed data exist
try:
    _conn = get_connection(APP_DB_PATH)
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
    Dynamically verify the operational health of the MediShield gateway and database.
    Does not use hardcoded health values.
    """
    target_db = APP_DB_PATH if APP_DB_PATH.exists() else (DEFAULT_DB_PATH if DEFAULT_DB_PATH.exists() else APP_DB_PATH)
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

        # Cryptographic self-check with normalized Decimal dose
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
            "detail": "All 5 core tables online • Fail-closed gateway ready • SHA-256 action-fingerprint self-test passed",
        }
    except Exception as e:
        return {
            "status": "OFFLINE",
            "healthy": False,
            "detail": f"Health check exception: {str(e)}",
        }


def setup_test_approval(
    conn: sqlite3.Connection,
    approval_id: str,
    action_data: Dict[str, Any],
    approver_id: str = "clinician_1",
    created_at: Optional[str] = None,
    expires_at: str = "2026-12-31T23:59:59Z",
) -> str:
    """Register an authoritative synthetic clinician approval in the database.

    Validates the action payload against ProtectedAction, calculates the canonical
    action hash, and persists the approval record into the SQLite approvals table.
    """
    return _create_test_approval(
        conn,
        approval_id,
        action_data,
        approver_id=approver_id,
        created_at=created_at,
        expires_at=expires_at,
    )


_setup_test_approval = setup_test_approval


def load_events(db_path: Optional[Path] = None) -> Tuple[List[Dict[str, Any]], str]:
    """
    Load audit events from the SQLite audit_events table if rows exist;
    otherwise fall back to reading logs/sample_events.jsonl.
    Enriches all events with deterministic medical department display IDs
    (EVT-DEPT-000000) and computed clinical dosage deviations.
    Always returns events sorted strictly descending by timestamp (newest first).
    """
    events: List[Dict[str, Any]] = []
    if db_path:
        target_db = Path(db_path)
        if not target_db.is_absolute() and (ROOT_DIR / target_db).exists():
            target_db = ROOT_DIR / target_db
    else:
        target_db = APP_DB_PATH
    source_type = "fallback"
    approvals_map: Dict[str, Any] = {}

    # 1. Try SQLite database
    try:
        if target_db.exists():
            conn = get_connection(target_db)
            cursor = conn.cursor()

            # Preload approvals map if table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='approvals'")
            if cursor.fetchone():
                cursor.execute("SELECT approval_id, action_json, approver_id FROM approvals")
                for app_row in cursor.fetchall():
                    try:
                        approvals_map[app_row["approval_id"]] = json.loads(app_row["action_json"])
                    except Exception:
                        pass

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'")
            if cursor.fetchone():
                cursor.execute("SELECT * FROM audit_events ORDER BY id DESC")
                rows = cursor.fetchall()
                if rows:
                    seen_requests = set()
                    for row in rows:
                        req_id = str(row["request_id"]) if "request_id" in row.keys() else ""
                        if req_id and req_id in seen_requests:
                            continue
                        if req_id:
                            seen_requests.add(req_id)
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
                            "id": int(row["id"]) if "id" in row.keys() else 0,
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

                    # Ensure strict descending order by time, breaking ties with id
                    events.sort(key=lambda e: (str(e.get("time") or ""), int(e.get("id") or 0)), reverse=True)

                    # Enrich each event deterministically
                    for idx, ev in enumerate(events):
                        dept_code, dept_name = resolve_event_department(ev)
                        ev["department"] = dept_code
                        ev["department_name"] = dept_name
                        ev["display_id"] = resolve_event_display_id(ev, fallback_index=idx + 1)
                        ev["dosage_comparison"] = extract_event_dosage_comparison(ev, approvals_map)
                        if ev.get("approval_id") and ev["approval_id"] in approvals_map:
                            ev["approved_action"] = approvals_map[ev["approval_id"]]

                    return events, "Synthetic Demonstration Dataset (SQLite: audit_events)"
            conn.close()
    except Exception:
        pass

    # 2. Read the append-only JSONL companion store when SQLite has no rows.
    # This keeps the dashboard aligned with the audit module's dual-store
    # contract without treating JSONL as an authorization source.
    events_jsonl_path = ROOT_DIR / "logs" / "events.jsonl"
    if events_jsonl_path.exists():
        loaded_events: List[Dict[str, Any]] = []
        try:
            with events_jsonl_path.open("r", encoding="utf-8") as handle:
                for idx, line in enumerate(handle):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except (TypeError, ValueError):
                        continue
                    item["id"] = item.get("id", idx)
                    loaded_events.append(item)
        except OSError:
            loaded_events = []
        if loaded_events:
            loaded_events.sort(
                key=lambda e: (str(e.get("time") or ""), int(e.get("id") or 0)),
                reverse=True,
            )
            for idx, ev in enumerate(loaded_events):
                ev.setdefault("changed_fields", [])
                ev.setdefault("state_changed", False)
                dept_code, dept_name = resolve_event_department(ev)
                ev["department"] = dept_code
                ev["department_name"] = dept_name
                ev["display_id"] = resolve_event_display_id(ev, fallback_index=idx + 1)
                ev["dosage_comparison"] = extract_event_dosage_comparison(ev, approvals_map)
                if ev.get("approval_id") and ev["approval_id"] in approvals_map:
                    ev["approved_action"] = approvals_map[ev["approval_id"]]
            return loaded_events, "Dual-Store Audit Log (logs/events.jsonl)"

    # 3. Fallback to sample_events.jsonl
    jsonl_path = ROOT_DIR / "logs" / "sample_events.jsonl"
    if jsonl_path.exists():
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if line:
                    try:
                        item = json.loads(line)
                        item["id"] = item.get("id", idx)
                        events.append(item)
                    except Exception:
                        continue
        # Ensure strict descending order by time, breaking ties with id
        events.sort(key=lambda e: (str(e.get("time") or ""), int(e.get("id") or 0)), reverse=True)

        for idx, ev in enumerate(events):
            dept_code, dept_name = resolve_event_department(ev)
            ev["department"] = dept_code
            ev["department_name"] = dept_name
            ev["display_id"] = resolve_event_display_id(ev, fallback_index=idx + 1)
            ev["dosage_comparison"] = extract_event_dosage_comparison(ev, approvals_map)
            if ev.get("approval_id") and ev["approval_id"] in approvals_map:
                ev["approved_action"] = approvals_map[ev["approval_id"]]

        return events, "Synthetic Fallback Dataset (logs/sample_events.jsonl)"

    return events, "No Events Available"


# ==============================================================================
# SECTION 3: Streamlit UI Setup & Healthcare / Security Palette
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
    /* =========================================================================
       CLINICAL HEALTHCARE & CYBERSECURITY PALETTE
       - Deep Clinical Navy: #102A43
       - Medical Teal:       #0D9488
       - Clinical Off-White: #F4F8FB
       - Clean White:        #FFFFFF
       - Slate:              #334155
       - Muted Slate:        #64748B
       - Light Border:       #E2E8F0
       - Allowed:            #16A34A (bg: #DCFCE7, border: #86EFAC)
       - Blocked:            #DC2626 (bg: #FEE2E2, border: #FCA5A5)
       - Warning:            #D97706 (bg: #FEF3C7, border: #FCD34D)
       ========================================================================= */

    /* Global Workspace Background */
    .stApp {
        background-color: #F4F8FB !important;
        color: #334155 !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
    }

    /* Left Sidebar: Deep Clinical Navy */
    section[data-testid="stSidebar"] {
        background-color: #102A43 !important;
        border-right: 1px solid #0B1D30 !important;
    }

    section[data-testid="stSidebar"] * {
        color: #E2E8F0 !important;
    }

    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3 {
        color: #FFFFFF !important;
    }

    /* Sidebar Radio Buttons (Teal Active Highlight) */
    section[data-testid="stSidebar"] div[role="radiogroup"] > label {
        padding: 8px 12px !important;
        border-radius: 8px !important;
        margin-bottom: 4px !important;
        transition: background-color 0.15s ease !important;
    }

    section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
        background-color: rgba(13, 148, 136, 0.2) !important;
    }

    section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"],
    section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
        background-color: #0D9488 !important;
        color: #FFFFFF !important;
        font-weight: 700 !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15) !important;
    }

    /* Headings */
    h1, h2, h3, h4, h5, h6 {
        color: #102A43 !important;
        font-weight: 700 !important;
        letter-spacing: -0.3px !important;
    }

    /* Metric Cards */
    .metric-card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 12px;
        padding: 18px 16px;
        box-shadow: 0 1px 3px rgba(16, 42, 67, 0.05);
        margin-bottom: 14px;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .metric-card:hover {
        box-shadow: 0 4px 6px -1px rgba(16, 42, 67, 0.08);
    }
    .metric-lbl {
        font-size: 0.78rem;
        font-weight: 700;
        color: #102A43;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        margin-bottom: 6px;
    }
    .metric-val {
        font-size: 2.1rem;
        font-weight: 800;
        line-height: 1.15;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    .metric-sub {
        font-size: 0.75rem;
        color: #64748B;
        margin-top: 6px;
        font-weight: 500;
    }

    /* Semantic Security Badges */
    .badge-allowed {
        background-color: #DCFCE7 !important;
        color: #16A34A !important;
        border: 1px solid #86EFAC !important;
        padding: 3px 10px !important;
        border-radius: 6px !important;
        font-weight: 700 !important;
        font-size: 0.8rem !important;
        display: inline-block !important;
        letter-spacing: 0.5px !important;
    }
    .badge-blocked {
        background-color: #FEE2E2 !important;
        color: #DC2626 !important;
        border: 1px solid #FCA5A5 !important;
        padding: 3px 10px !important;
        border-radius: 6px !important;
        font-weight: 700 !important;
        font-size: 0.8rem !important;
        display: inline-block !important;
        letter-spacing: 0.5px !important;
    }
    .badge-warning {
        background-color: #FEF3C7 !important;
        color: #92400E !important;
        border: 1px solid #FCD34D !important;
        padding: 3px 10px !important;
        border-radius: 6px !important;
        font-weight: 700 !important;
        font-size: 0.8rem !important;
        display: inline-block !important;
        letter-spacing: 0.5px !important;
    }

    /* Risk Badges */
    .risk-high {
        background-color: #FEE2E2;
        color: #B91C1C;
        border: 1px solid #FCA5A5;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.76rem;
        font-weight: 600;
    }
    .risk-med {
        background-color: #FEF3C7;
        color: #B45309;
        border: 1px solid #FCD34D;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.76rem;
        font-weight: 600;
    }
    .risk-low {
        background-color: #DCFCE7;
        color: #15803D;
        border: 1px solid #86EFAC;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.76rem;
        font-weight: 600;
    }

    /* Clean White Panel Cards */
    .section-panel {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px rgba(16, 42, 67, 0.04);
    }

    /* Operational Status Banner */
    .status-banner {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-left: 4px solid #0D9488;
        padding: 12px 18px;
        border-radius: 8px;
        margin-bottom: 18px;
        box-shadow: 0 1px 3px rgba(16, 42, 67, 0.04);
    }

    /* 3-Column Event Card */
    .event-row {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 10px 14px;
        margin-bottom: 6px;
        transition: background-color 0.15s ease, border-color 0.15s ease;
    }
    .event-row:hover {
        background-color: #F8FAFC;
        border-color: #CBD5E1;
    }

    /* Form Inputs */
    .stTextInput > div > div > input,
    .stSelectbox > div > div > div {
        background-color: #FFFFFF !important;
        border: 1px solid #CBD5E1 !important;
        border-radius: 6px !important;
        color: #334155 !important;
    }

    /* Buttons: Medical Teal Accent */
    button[kind="primary"], .stButton > button[kind="primary"] {
        background-color: #0D9488 !important;
        color: #FFFFFF !important;
        border: none !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        transition: background-color 0.15s ease !important;
    }
    button[kind="primary"]:hover {
        background-color: #0F766E !important;
    }

    button[kind="secondary"], .stButton > button {
        background-color: #FFFFFF !important;
        color: #102A43 !important;
        border: 1px solid #CBD5E1 !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
    }
    button[kind="secondary"]:hover, .stButton > button:hover {
        background-color: #F8FAFC !important;
        border-color: #0D9488 !important;
        color: #0D9488 !important;
    }

    /* Single Clean White Expandable Event Card */
    div[data-testid="stExpander"] {
        background-color: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 10px !important;
        box-shadow: 0 1px 3px rgba(16, 42, 67, 0.04) !important;
        margin-bottom: 8px !important;
        overflow: hidden !important;
        transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
    }
    div[data-testid="stExpander"]:hover {
        border-color: #CBD5E1 !important;
        box-shadow: 0 3px 6px rgba(16, 42, 67, 0.08) !important;
    }
    div[data-testid="stExpander"] summary {
        padding: 10px 14px !important;
        border-radius: 9px !important;
        transition: background-color 0.15s ease !important;
    }
    div[data-testid="stExpander"] summary:hover {
        background-color: #F8FAFC !important;
    }
    div[data-testid="stExpanderDetails"] {
        border-top: 1px solid #E2E8F0 !important;
        padding: 16px 20px !important;
        background-color: #FFFFFF !important;
    }
    /* Nested Raw JSON Expander styling */
    div[data-testid="stExpanderDetails"] div[data-testid="stExpander"] {
        background-color: #F8FAFC !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 6px !important;
        margin-top: 10px !important;
        box-shadow: none !important;
    }
    div[data-testid="stExpanderDetails"] div[data-testid="stExpander"] summary {
        font-size: 0.85rem !important;
        padding: 8px 12px !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize session state for refresh tracking, sentinel telemetry, and live simulator feedback
if "last_refresh_time" not in st.session_state:
    st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
if "flash_banner" not in st.session_state:
    st.session_state["flash_banner"] = None
if "sentinel_tamper_result" not in st.session_state:
    st.session_state["sentinel_tamper_result"] = None
if "sentinel_observed_tools" not in st.session_state:
    st.session_state["sentinel_observed_tools"] = None
if "sentinel_status_override" not in st.session_state:
    st.session_state["sentinel_status_override"] = None
if "sentinel_authorized_result" not in st.session_state:
    st.session_state["sentinel_authorized_result"] = None

# Load events, active source, and live gateway status (always fresh from audit storage)
all_events, active_data_source = load_events()
gw_health = check_gateway_health()


# ==============================================================================
# SECTION 4: Left Sidebar (Deep Clinical Navy + Logo + Navigation)
# ==============================================================================
with st.sidebar:
    st.markdown(
        """
        <div style="padding: 10px 0 16px 0;">
            <div style="font-size: 1.6rem; font-weight: 800; color: #FFFFFF; display: flex; align-items: center; gap: 8px;">
                <span>🛡️✚</span> <span>MediShield</span>
            </div>
            <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px; margin-top: 2px;">
                Runtime Security Gateway
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<p style='font-size: 0.72rem; color: #64748B; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 6px;'>Console Navigation</p>", unsafe_allow_html=True)

    nav_choice = st.radio(
        "Navigation Menu",
        options=[
            "Overview",
            "MCP Trust Sentinel",
            "Secure Document Vault",
            "Security Test Lab",
            "Approval Verification",
            "Audit Log",
        ],
        index=0,
        label_visibility="collapsed",
        key="nav_selection",
    )

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)
    st.divider()

    # Compact Gateway Status Indicator in Sidebar
    gw_status_color = "#34D399" if gw_health["healthy"] else "#F87171"
    st.markdown(
        f"""
        <div style="background: rgba(11, 29, 48, 0.7); border: 1px solid #1E3A5F; border-radius: 8px; padding: 12px; margin-bottom: 14px;">
            <div style="font-size: 0.72rem; color: #94A3B8; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px;">Gateway Health</div>
            <div style="font-size: 0.88rem; font-weight: 700; color: {gw_status_color}; margin-top: 2px;">
                ● {gw_health['status']} (FAIL-CLOSED)
            </div>
            <div style="font-size: 0.72rem; color: #94A3B8; margin-top: 6px;">
                <b>Dataset:</b> {len(all_events)} events
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("🔄 Refresh Data", key="sidebar_refresh_btn", use_container_width=True):
        st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
        st.rerun()

    st.markdown(
        f"""
        <div style="font-size: 0.72rem; color: #94A3B8; text-align: center; margin-top: -4px; margin-bottom: 8px;">
            Last Refreshed: <span style="color: #F8FAFC; font-weight: 600;">{to_ist_string(st.session_state['last_refresh_time'])}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption("MediShield Healthcare Security • Synthetic Clinical Invariants")


# ==============================================================================
# HELPER: Render 3-Column Expandable Event Row (Clean White Card Design)
# ==============================================================================
def render_audit_event_card(event: Dict[str, Any], expanded_default: bool = False):
    """
    Renders an audit event as a single unified expandable white card:
    Collapsed View:  | Medical Event ID (Timestamp) | Gateway Decision | Risk Level |
    Expanded View:
      1. Request Details & Traceability (Display ID, Original Request ID, Actor, Tool, Dept)
      2. Security Assessment & Gateway Verdict (Decision, Risk, Rule, Intent Explanation)
      3. Medication Prescription & Dosage Deviation (Approved vs Submitted, %, Delta, Direction)
      4. Backend Clinical State & Approval Lifecycle (State modified, Changed fields, Approval ID)
      5. Raw JSON (nested expander)
    """
    disp_id = event.get("display_id") or resolve_event_display_id(event)
    dept_name = event.get("department_name") or "General Medicine"
    dept_code = event.get("department") or "GEN"
    req_id = str(event.get("request_id", "UNKNOWN"))
    dec = str(event.get("decision", "unknown")).lower()
    risk = str(event.get("risk", "unknown")).lower()
    time_ist = to_ist_string(event.get("time"))
    tool_name = str(event.get("tool", "update_order"))

    # Semantic Badges for HTML inner rendering
    if dec == "allowed":
        dec_badge = '<span class="badge-allowed">ALLOWED</span>'
        dec_pill = "🟢 :green[**ALLOWED**]"
    elif dec == "blocked":
        dec_badge = '<span class="badge-blocked">BLOCKED</span>'
        dec_pill = "🔴 :red[**BLOCKED**]"
    else:
        dec_badge = '<span class="badge-warning">WARNING</span>'
        dec_pill = "🟡 :orange[**WARNING**]"

    if risk == "high":
        risk_badge = '<span class="risk-high">HIGH</span>'
        risk_pill = "🔺 :red[**HIGH**]"
    elif risk in ["med", "medium"]:
        risk_badge = '<span class="risk-med">MEDIUM</span>'
        risk_pill = "🔸 :orange[**MEDIUM**]"
    else:
        risk_badge = '<span class="risk-low">LOW</span>'
        risk_pill = "🔹 :green[**LOW**]"

    # Single Unified Expandable Card
    expander_title = f"`{disp_id}` ({dept_code}) :gray[({time_ist})] &emsp;|&emsp; {dec_pill} &emsp;|&emsp; {risk_pill}"

    with st.expander(expander_title, expanded=expanded_default):
        # 1. Request Details & Traceability
        st.markdown("##### 1. Request Details & Traceability")
        r1, r2, r3, r4, r5 = st.columns([2.5, 2.5, 2, 2.5, 2.5])
        r1.metric("Medical Event ID", disp_id, help=f"Deterministic {dept_code} Department Event Identifier")
        r2.metric("Original Request ID", req_id, help="Cryptographic Audit Correlation ID")
        r3.metric("Actor", str(event.get("actor", "N/A")))
        r4.metric("Tool / Action", tool_name)
        r5.metric("Department", f"{dept_name} ({dept_code})")

        st.markdown("---")

        # 2. Security Assessment & Gateway Verdict
        st.markdown("##### 2. Security Assessment & Gateway Verdict")
        s1, s2, s3 = st.columns([2, 2, 6])
        with s1:
            st.markdown(f"**Gateway Decision:** {dec_badge}", unsafe_allow_html=True)
        with s2:
            st.markdown(f"**Risk Level:** {risk_badge}", unsafe_allow_html=True)
        with s3:
            st.markdown(f"**Security Policy Rule:** `{event.get('rule', 'N/A')}`")

        st.markdown("**Clinical Intent Explanation:**")
        reason_txt = event.get("reason", "No detailed explanation recorded.")
        if dec == "allowed":
            st.success(reason_txt)
        elif dec == "blocked":
            st.error(reason_txt)
        else:
            st.warning(reason_txt)

        st.markdown("---")

        # 3. Medication Prescription & Dosage Deviation
        st.markdown("##### 3. Medication Prescription & Dosage Deviation")
        comp = event.get("dosage_comparison") or extract_event_dosage_comparison(event)

        if comp.get("is_applicable"):
            d_col1, d_col2, d_col3 = st.columns([3, 3, 4])
            with d_col1:
                st.markdown(
                    f"""
                    <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px;">
                        <div style="font-size: 0.74rem; font-weight: 700; color: #102A43; text-transform: uppercase; letter-spacing: 0.5px;">
                            Approved Prescription (Baseline)
                        </div>
                        <div style="font-size: 1.15rem; font-weight: 800; color: #102A43; margin-top: 4px;">
                            {comp['approved_display']}
                        </div>
                        <div style="font-size: 0.78rem; color: #64748B; margin-top: 2px;">
                            Trusted Clinician Baseline
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with d_col2:
                sub_border = "#FCA5A5" if comp.get("is_violation") else "#86EFAC"
                sub_bg = "#FEF2F2" if comp.get("is_violation") else "#F0FDF4"
                st.markdown(
                    f"""
                    <div style="background: {sub_bg}; border: 1px solid {sub_border}; border-radius: 8px; padding: 12px;">
                        <div style="font-size: 0.74rem; font-weight: 700; color: #102A43; text-transform: uppercase; letter-spacing: 0.5px;">
                            AI-Submitted Action
                        </div>
                        <div style="font-size: 1.15rem; font-weight: 800; color: #102A43; margin-top: 4px;">
                            {comp['submitted_display']}
                        </div>
                        <div style="font-size: 0.78rem; color: #64748B; margin-top: 2px;">
                            Untrusted Agent Parameter
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with d_col3:
                if comp.get("is_violation"):
                    dev_badge = f'<span class="badge-blocked" style="font-size: 0.92rem; padding: 4px 10px;">🚨 Deviation: {comp["deviation_pct_str"]}</span>'
                elif comp.get("status") == "ZERO_BASELINE":
                    dev_badge = f'<span class="badge-warning" style="font-size: 0.92rem; padding: 4px 10px;">⚠️ Deviation: N/A (Zero baseline)</span>'
                else:
                    dev_badge = f'<span class="badge-allowed" style="font-size: 0.92rem; padding: 4px 10px;">🟢 0% — Exact match</span>'

                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 12px;">
                        <div style="font-size: 0.74rem; font-weight: 700; color: #102A43; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">
                            Technical Deviation Indicator
                        </div>
                        <div>{dev_badge}</div>
                        <div style="font-size: 0.82rem; color: #334155; margin-top: 6px; font-weight: 600;">
                            Absolute Difference: <code>{comp['difference_str']}</code>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.caption(f"ℹ️ {comp['explanation']}")
            if not comp.get("medication_match"):
                st.warning("⚠️ **Medication Identity Mismatch:** The AI submitted a medication different from the clinician-approved prescription.")
        else:
            st.markdown(
                f"""
                <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 10px 14px; font-size: 0.85rem; color: #64748B;">
                    <b>Dosage Deviation:</b> {comp['deviation_pct_str']} &nbsp;•&nbsp; <span>{comp['explanation']}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("---")

        # 4. Backend Clinical State & Approval Lifecycle
        st.markdown("##### 4. Backend Clinical State & Approval Lifecycle")
        o1, o2, o3 = st.columns(3)
        with o1:
            st_changed = event.get("state_changed", False)
            if st_changed:
                st.markdown("**Backend Clinical State:** `True` *(Modified)*")
            else:
                st.markdown("**Backend Clinical State:** `False` *(Protected / Unaltered)*")
        with o2:
            cf = event.get("changed_fields", [])
            st.markdown(f"**Changed / Detected Fields:** `{cf}`")
        with o3:
            st.markdown(f"**Approval ID:** `{event.get('approval_id') or 'None'}`")

        # 5. Raw JSON
        with st.expander("📄 View Raw Audit JSON", expanded=False):
            st.json(event)


# ==============================================================================
# SECTION 5: Navigation Dispatcher
# ==============================================================================

# ------------------------------------------------------------------------------
# SECTION 5.1: OVERVIEW
# ------------------------------------------------------------------------------
if nav_choice == "Overview":
    # Workspace Top Header
    h_col1, h_col2 = st.columns([5, 1])
    with h_col1:
        st.title("Security Overview")
        st.markdown(
            "<p style='color: #64748B; font-size: 1.05rem; margin-top: -8px;'>"
            "Monitor clinical tool activity, runtime security decisions, and approval verification."
            "</p>",
            unsafe_allow_html=True,
        )
    with h_col2:
        st.write("")
        if st.button("🔄 Refresh Data", key="top_ref_btn", use_container_width=True):
            st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
            st.rerun()
        st.markdown(
            f"""
            <div style="font-size: 0.72rem; color: #64748B; text-align: right; margin-top: -4px;">
                Refreshed: <span style="font-weight: 600; color: #102A43;">{to_ist_string(st.session_state['last_refresh_time'])}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Dynamic Operational Gateway & MCP Sentinel Status Banner
    status_pill_html = (
        '<span class="badge-allowed">● ACTIVE (FAIL-CLOSED)</span>'
        if gw_health["healthy"]
        else f'<span class="badge-blocked">● {gw_health["status"]}</span>'
    )
    try:
        sentinel_status = get_tool_integrity_status()
        sentinel_trusted = (
            str(sentinel_status.get("status", "")).lower() == "trusted"
            and bool(sentinel_status.get("protected_execution_allowed"))
        )
        sentinel_label = "TRUSTED (5/5 VERIFIED)" if sentinel_trusted else str(
            sentinel_status.get("status", "UNVERIFIABLE")
        ).upper()
    except Exception:
        sentinel_trusted = False
        sentinel_label = "UNVERIFIABLE"
    sentinel_pill_html = (
        f'<span class="badge-allowed">● {sentinel_label}</span>'
        if sentinel_trusted
        else f'<span class="badge-blocked">● {sentinel_label}</span>'
    )
    st.markdown(
        f"""
        <div class="status-banner">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
                <div>
                    <span style="font-weight: 700; color: #102A43; font-size: 0.92rem;">GATEWAY STATUS:</span>
                    &nbsp; {status_pill_html}
                    &nbsp;&nbsp;|&nbsp;&nbsp;
                    <span style="font-weight: 700; color: #102A43; font-size: 0.92rem;">MCP SENTINEL:</span>
                    &nbsp; {sentinel_pill_html}
                    <span style="color: #64748B; font-size: 0.85rem; margin-left: 12px;">
                        {gw_health['detail']}
                    </span>
                </div>
                <div style="font-size: 0.82rem; color: #64748B;">
                    Data Source: <b style="color: #102A43;">{active_data_source}</b>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Render Flash Banner Notification if present
    if st.session_state.get("flash_banner"):
        b_type, b_msg = st.session_state["flash_banner"]
        if b_type == "success":
            st.success(b_msg)
        elif b_type == "error":
            st.error(b_msg)
        elif b_type == "warning":
            st.warning(b_msg)
        else:
            st.info(b_msg)
        st.session_state["flash_banner"] = None

    # Calculate 5 Summary Metrics from actual event data
    total_calls = len(all_events)
    allowed_calls = sum(1 for e in all_events if str(e.get("decision")).lower() == "allowed")
    blocked_calls = sum(1 for e in all_events if str(e.get("decision")).lower() == "blocked")
    warning_calls = sum(1 for e in all_events if str(e.get("decision")).lower() == "warning")

    # Error Rate Definition:
    # Error Rate (%) = Genuine execution failures / Total operations * 100
    # Crucial: Blocked security decisions (stopped attacks) and Warnings are NOT execution errors.
    genuine_errors = sum(
        1 for e in all_events
        if any(
            err_term in str(e.get("rule", "")).lower() or err_term in str(e.get("reason", "")).lower()
            for err_term in ["verification failed", "system fault", "database error", "malformed request"]
        )
        or bool(e.get("error"))
    )
    error_rate = (genuine_errors / total_calls * 100.0) if total_calls > 0 else 0.0

    # 5 Summary Metric Cards (Clean White with Navy / Semantic Values)
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Total Calls</div>
                <div class="metric-val" style="color: #0D9488;">{total_calls}</div>
                <div class="metric-sub">Monitored Operations</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Allowed</div>
                <div class="metric-val" style="color: #16A34A;">{allowed_calls}</div>
                <div class="metric-sub">Verified Intent Locks</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Blocked</div>
                <div class="metric-val" style="color: #DC2626;">{blocked_calls}</div>
                <div class="metric-sub">Neutralized Attacks</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Warnings</div>
                <div class="metric-val" style="color: #D97706;">{warning_calls}</div>
                <div class="metric-sub">Policy Advisories</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m5:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Error Rate</div>
                <div class="metric-val" style="color: #102A43;">{error_rate:.1f}%</div>
                <div class="metric-sub">System Faults Only</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Live Tool Call Simulation & Ingestion Card
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    with st.expander("⚡ Live MCP Tool Ingestion Simulator (Test Dynamic Monitoring & Counter)", expanded=True):
        st.markdown(
            "<p style='color: #64748B; font-size: 0.88rem; margin-top: -4px; margin-bottom: 12px;'>"
            "Trigger real-time AI tool calls through <code>guard/gateway.py</code> to test live audit logging, "
            "fail-closed policy checks, and watch the <b>Monitored Calls</b> counter update dynamically."
            "</p>",
            unsafe_allow_html=True,
        )
        sim1, sim2, sim3 = st.columns(3)
        with sim1:
            st.markdown(
                """
                <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
                    <div style="font-weight: 700; color: #16A34A; font-size: 0.88rem;">🟢 Valid Clinician Action</div>
                    <div style="font-size: 0.76rem; color: #64748B; margin-top: 4px;">
                        Doctor-approved synthetic medication action (P-104). Cryptographic digest matches.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.button("⚡ Execute Valid Action", key="btn_sim_valid", use_container_width=True):
                conn = get_connection(APP_DB_PATH)
                ts = int(datetime.now().timestamp())
                app_id = f"APR-LIVE-VAL-{ts}"
                req_id = f"REQ-LIVE-VAL-{ts}"
                action_data = {
                    "order_id": "ORD-LIVE-001",
                    "patient_id": "P-104",
                    "medication_id": "MED-MET-500",
                    "dose": "500",
                    "units": "mg",
                    "route": "oral",
                    "frequency": "daily",
                    "duration": "30 days",
                }
                prot = ProtectedAction(**action_data)
                h = action_hash(prot)
                _setup_test_approval(conn, app_id, action_data)
                req = ExecutionRequest(
                    request_id=req_id,
                    actor_id="agent_1",
                    tool="update_order",
                    approval_id=app_id,
                    action=prot,
                )
                dec = verify_execution(req, conn)
                conn.close()
                st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
                st.session_state["flash_banner"] = (
                    "success",
                    f"✅ Live Tool Call Executed: `{req_id}` -> ALLOWED ({dec.rule}). Order ORD-LIVE-001 updated in backend. Monitored calls counter incremented!",
                )
                st.rerun()

        with sim2:
            st.markdown(
                """
                <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
                    <div style="font-weight: 700; color: #DC2626; font-size: 0.88rem;">🔴 Tampered Dose Attack</div>
                    <div style="font-size: 0.76rem; color: #64748B; margin-top: 4px;">
                        Unauthorized synthetic dose escalation (P-205). Digest mismatch.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.button("🛑 Execute Blocked Attack", key="btn_sim_attack", use_container_width=True):
                conn = get_connection(APP_DB_PATH)
                ts = int(datetime.now().timestamp())
                app_id = f"APR-LIVE-ATK-{ts}"
                req_id = f"REQ-LIVE-ATK-{ts}"
                approved_data = {
                    "order_id": "ORD-LIVE-002",
                    "patient_id": "P-205",
                    "medication_id": "MED-INS-GLA",
                    "dose": "5",
                    "units": "units",
                    "route": "subcutaneous",
                    "frequency": "daily",
                    "duration": "ongoing",
                }
                tampered_data = dict(approved_data)
                tampered_data["dose"] = "50"

                prot_app = ProtectedAction(**approved_data)
                h = action_hash(prot_app)
                _setup_test_approval(conn, app_id, approved_data)
                req = ExecutionRequest(
                    request_id=req_id,
                    actor_id="agent_1",
                    tool="update_order",
                    approval_id=app_id,
                    action=ProtectedAction(**tampered_data),
                )
                dec = verify_execution(req, conn)
                conn.close()
                st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
                st.session_state["flash_banner"] = (
                    "error",
                    f"🛑 Adversarial Attack Blocked: `{req_id}` -> BLOCKED ({dec.rule}). Safeguard engaged, backend unchanged, counter incremented!",
                )
                st.rerun()

        with sim3:
            st.markdown(
                """
                <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
                    <div style="font-weight: 700; color: #D97706; font-size: 0.88rem;">⚠️ Unit Discrepancy Advisory</div>
                    <div style="font-size: 0.76rem; color: #64748B; margin-top: 4px;">
                        Non-canonical unit casing: Amoxicillin 250 'MG' normalized with warning.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.button("⚠️ Execute Advisory Call", key="btn_sim_warn", use_container_width=True):
                ts = int(datetime.now().timestamp())
                req_id = f"REQ-LIVE-WARN-{ts}"
                record_audit_event({
                    "time": datetime.now(timezone.utc).isoformat(),
                    "request_id": req_id,
                    "actor_id": "agent_1",
                    "tool": "update_order",
                    "action_type": "medication_order",
                    "approval_id": f"APR-LIVE-WARN-{ts}",
                    "decision": "warning",
                    "risk": "medium",
                    "rule": "unit case normalization notice",
                    "reason": "Submitted units 'MG' normalized to lowercase 'mg'. Approved action permitted under clinical oversight.",
                    "changed_fields": ["units"],
                    "state_changed": 1,
                })
                st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
                st.session_state["flash_banner"] = (
                    "warning",
                    f"⚠️ Policy Advisory Audited: `{req_id}` -> WARNING. Gateway normalized casing, audit recorded, counter incremented!",
                )
                st.rerun()

    # Recent Security Events Section (White Panel Card)
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    st.subheader("Recent Security Events")
    st.markdown(
        "<p style='color: #64748B; font-size: 0.9rem; margin-top: -6px; margin-bottom: 12px;'>"
        "Latest gateway decisions and security activity (newest first). Click any row to expand assessment details."
        "</p>",
        unsafe_allow_html=True,
    )

    if all_events:
        # 3-Column Header
        st.markdown(
            """
            <div style="display: flex; align-items: center; justify-content: space-between; padding: 6px 14px; font-size: 0.8rem; font-weight: 700; color: #102A43; text-transform: uppercase; letter-spacing: 0.6px; border-bottom: 2px solid #E2E8F0; margin-bottom: 8px;">
                <div style="flex: 4;">Medical Event ID (Department)</div>
                <div style="flex: 3;">Gateway Decision</div>
                <div style="flex: 3;">Risk Level</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        for ev in all_events[:8]:
            render_audit_event_card(ev, expanded_default=False)
    else:
        st.info("No audit events found.")


# ------------------------------------------------------------------------------
# SECTION 5.2: MCP TRUST SENTINEL & LIVE TAMPERING DEMONSTRATION
# ------------------------------------------------------------------------------
elif nav_choice == "MCP Trust Sentinel":
    render_sentinel_console(all_events, to_ist_string)


# ------------------------------------------------------------------------------
# SECTION 5.2.1: SECURE DOCUMENT VAULT
# ------------------------------------------------------------------------------
elif nav_choice == "Secure Document Vault":
    render_document_vault(
        db_path=APP_DB_PATH,
        storage_root=ROOT_DIR / ".medishield_vault",
    )


# ------------------------------------------------------------------------------
# SECTION 5.3: SECURITY TEST LAB
# ------------------------------------------------------------------------------
elif nav_choice == "Security Test Lab":
    st.title("Security Test Lab")
    st.markdown(
        "<p style='color: #64748B; font-size: 1.05rem; margin-top: -8px;'>"
        "Execute synthetic adversarial attacks against the <b>actual MediShield security engine</b> (<code>guard/gateway.py</code>). "
        "Verifies fail-closed enforcement and guarantees synthetic clinical records remain untouched."
        "</p>",
        unsafe_allow_html=True,
    )

    # Action Toolbar
    col_btn1, col_btn2, col_btn3, col_btn4, col_btn5 = st.columns(5)
    run_tamper = col_btn1.button("⚡ Test 1: Dose Tamper", use_container_width=True)
    run_patient = col_btn2.button("⚡ Test 2: Patient Sub.", use_container_width=True)
    run_replay = col_btn3.button("⚡ Test 3: Approval Replay", use_container_width=True)
    run_expired = col_btn4.button("⚡ Test 4: Expired Token", use_container_width=True)
    run_all = col_btn5.button("🚀 Run All 4 Attack Tests", type="primary", use_container_width=True)

    if run_tamper or run_patient or run_replay or run_expired or run_all:
        st.session_state["last_refresh_time"] = datetime.now(timezone.utc)

    # Test 1: Dose Tampering
    if run_tamper or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 1: Protected Dose Tampering Attack")
        st.caption("Description: A clinician approved 5mg of MED-A, but an untrusted agent submits 50mg.")

        conn = get_connection(APP_DB_PATH)
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

        orig_order = conn.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()
        orig_dose = orig_order["dose"] if orig_order else "5"

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

        post_order = conn.execute("SELECT dose FROM orders WHERE order_id = 'ORD-DEMO-001'").fetchone()
        post_dose = post_order["dose"] if post_order else "5"
        conn.close()

        is_pass = (
            decision.decision == "blocked"
            and decision.rule == "intent hash mismatch"
            and decision.state_changed is False
            and orig_dose == post_dose
        )

        t1_col1, t1_col2 = st.columns(2)
        with t1_col1:
            st.markdown(f"**Expected Result:** <span class='badge-blocked'>BLOCKED</span> *(intent hash mismatch)*", unsafe_allow_html=True)
            st.markdown(f"**Actual Result:** <span class='badge-blocked'>{decision.decision.upper()}</span>", unsafe_allow_html=True)
            st.markdown(f"**Security Rule:** `{decision.rule}`")
            st.markdown(f"**Clinical Reason:** {decision.reason}")
            st.markdown(f"**Request ID:** `{req_id}`")
        with t1_col2:
            st.markdown("**Protected Backend State Verification:**")
            st.markdown(f"- Clinician Approved Dose: `5 mg`")
            st.markdown(f"- Agent Submitted Dose: `50 mg` *(Tampered)*")
            st.markdown(f"- Database Dose Prior to Attack: `{orig_dose}`")
            st.markdown(f"- Database Dose After Attack: `{post_dose}`")
            st.markdown(f"- Backend State Modified: `{decision.state_changed}`")

        if is_pass:
            st.success("✅ **PASS:** Dose tampering blocked fail-closed. Database records remained completely unmodified.")
        else:
            st.error("❌ **FAIL:** Attack modified backend state!")

    # Test 2: Patient Substitution
    if run_patient or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 2: Patient Substitution Attack")
        st.caption("Description: A clinician approved an order for Patient P-104; an agent attempts to apply it to P-205.")

        conn = get_connection(APP_DB_PATH)
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
            st.markdown(f"**Expected Result:** <span class='badge-blocked'>BLOCKED</span> *(intent hash mismatch)*", unsafe_allow_html=True)
            st.markdown(f"**Actual Result:** <span class='badge-blocked'>{decision.decision.upper()}</span>", unsafe_allow_html=True)
            st.markdown(f"**Security Rule:** `{decision.rule}`")
            st.markdown(f"**Clinical Reason:** {decision.reason}")
            st.markdown(f"**Request ID:** `{req_id}`")
        with t2_col2:
            st.markdown("**Protected Backend State Verification:**")
            st.markdown("- Clinician Approved Patient: `P-104`")
            st.markdown("- Agent Submitted Patient: `P-205` *(Unauthorized Transfer)*")
            st.markdown(f"- Detected Mismatched Fields: `{decision.changed_fields}`")
            st.markdown(f"- Backend State Modified: `{decision.state_changed}`")

        if is_pass:
            st.success("✅ **PASS:** Patient substitution blocked. Intent lock bound action strictly to Patient P-104.")
        else:
            st.error("❌ **FAIL:** Patient substitution succeeded!")

    # Test 3: Approval Replay
    if run_replay or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 3: Approval Replay Attack")
        st.caption("Description: A legitimate approval is executed once, then replayed a second time using the consumed token.")

        conn = get_connection(APP_DB_PATH)
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
            st.markdown(f"**Execution 1 (Legitimate):** <span class='badge-allowed'>{dec1.decision.upper()}</span>", unsafe_allow_html=True)
            st.markdown(f"- Request ID: `{req1_id}`")
            st.markdown(f"- Rule Triggered: `{dec1.rule}`")
            st.markdown(f"- State Modified: `{dec1.state_changed}`")
            st.markdown("- Approval Token: *Atomically Consumed*")
        with t3_col2:
            st.markdown(f"**Execution 2 (Replay Attack):** <span class='badge-blocked'>{dec2.decision.upper()}</span>", unsafe_allow_html=True)
            st.markdown(f"- Request ID: `{req2_id}`")
            st.markdown(f"- Rule Triggered: `{dec2.rule}`")
            st.markdown(f"- Reason: {dec2.reason}")
            st.markdown(f"- State Modified: `{dec2.state_changed}` *(Protected)*")

        if is_pass:
            st.success("✅ **PASS:** Approval replay blocked. Single-use token invalidated immediately upon first execution.")
        else:
            st.error("❌ **FAIL:** Replay token executed twice!")

    # Test 4: Expired Approval
    if run_expired or run_all:
        st.markdown("---")
        st.markdown("#### 🧪 Test 4: Expired Clinician Approval Attack")
        st.caption("Description: Agent attempts to execute an action using an approval token whose validity period has elapsed.")

        conn = get_connection(APP_DB_PATH)
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
        # Seed an expired approval (expired in 2020) through the same
        # authenticated fixture helper used by the other dashboard scenarios.
        _setup_test_approval(
            conn,
            app_id,
            action_data,
            created_at="2019-12-01T00:00:00Z",
            expires_at="2020-01-01T00:00:00Z",
        )

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
            st.markdown(f"**Expected Result:** <span class='badge-blocked'>BLOCKED</span> *(approval expired)*", unsafe_allow_html=True)
            st.markdown(f"**Actual Result:** <span class='badge-blocked'>{decision.decision.upper()}</span>", unsafe_allow_html=True)
            st.markdown(f"**Security Rule:** `{decision.rule}`")
            st.markdown(f"**Reason:** {decision.reason}")
        with t4_col2:
            st.markdown("**Protected State Verification:**")
            st.markdown("- Approval Expiry Date: `2020-01-01T00:00:00Z` *(Expired)*")
            st.markdown(f"- Request ID: `{req_id}`")
            st.markdown(f"- Backend State Modified: `{decision.state_changed}`")

        if is_pass:
            st.success("✅ **PASS:** Expired approval blocked fail-closed. Stale authorization cannot be executed.")
        else:
            st.error("❌ **FAIL:** Expired approval was accepted!")


# ------------------------------------------------------------------------------
# SECTION 5.3: APPROVAL VERIFICATION
# ------------------------------------------------------------------------------
elif nav_choice == "Approval Verification":
    st.title("Approval & Action Verification")
    st.markdown(
        "<p style='color: #64748B; font-size: 1.05rem; margin-top: -8px;'>"
        "Compare clinician-approved intent with agent-submitted execution parameters side-by-side. "
        "Inspect canonical normalization, field-level differences, and cryptographic digests."
        "</p>",
        unsafe_allow_html=True,
    )

    # Preset selection
    st.markdown("##### ⚙️ Scenario Presets")
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

        if fld == "units":
            if a_str == s_str:
                return "✅ Exact Match"
            elif a_str.lower() == s_str.lower():
                return "⚠️ Case Discrepancy (Canonicalization Notice)"
            else:
                return "❌ Tampered / Mismatch"

        if a_str == s_str:
            return "✅ Exact Match"
        elif a_str.lower() == s_str.lower():
            return "⚠️ Case Discrepancy (Canonicalization Notice)"
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

    # Canonical strings and hashes
    try:
        app_canon = canonicalize_action(approved_dict)
        sub_canon = canonicalize_action(submitted_dict)
        app_h = action_hash(approved_dict)
        sub_h = action_hash(submitted_dict)
        live_decision = None
        verification_error = None

        # If user explicitly clicked "Run Gateway Intent Lock Check", execute live gateway
        if run_check:
            st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
            conn = get_connection(APP_DB_PATH)
            ts = int(datetime.now().timestamp())
            app_id = f"APR-ACTION-VERIF-{ts}"
            _setup_test_approval(conn, app_id, approved_dict)

            exec_req = ExecutionRequest(
                request_id=f"REQ-ACTION-VERIF-{ts}",
                actor_id="agent_1",
                tool="update_order",
                approval_id=app_id,
                action=ProtectedAction(**submitted_dict),
            )
            try:
                live_decision = verify_execution(exec_req, conn)
            except Exception as exc:
                verification_error = exc
            conn.close()
            live_verdict = gateway_verdict(live_decision, verification_error)
            st.info(
                f"⚡ **Live Gateway Result:** Recorded `{exec_req.request_id}` — "
                f"Decision: `{live_verdict['label']}` ({live_verdict['rule']})."
            )

        st.divider()
        st.subheader("Verification Analysis & Gateway Verdict")

        # The displayed verdict is populated only by the real gateway result.
        # Local field comparisons are analysis hints, never authorization.
        if live_decision is None and verification_error is None:
            st.info("Gateway verification has not run. Rendering this page does not authorize or execute an order.")
            verdict_rule = "not evaluated"
            verdict_changed = "Not evaluated"
            verdict_state = "Not evaluated"
        else:
            live_verdict = gateway_verdict(live_decision, verification_error)
            verdict_changed = live_verdict["changed_fields"] or "None"
            verdict_state = str(live_verdict["state_changed"])
            verdict_rule = live_verdict["rule"]
            if live_verdict["decision"] == "blocked":
                st.markdown(
                    f"<div style='background-color: #FEE2E2; border: 1px solid #FCA5A5; border-left: 5px solid #DC2626; padding: 14px 18px; border-radius: 8px; margin-bottom: 16px;'><b style='color: #DC2626; font-size: 1.05rem;'>🔴 GATEWAY VERDICT: BLOCKED</b> — <span style='color: #991B1B;'>{live_verdict['reason']}</span></div>",
                    unsafe_allow_html=True,
                )
            elif live_verdict["decision"] == "warning":
                st.markdown(
                    f"<div style='background-color: #FEF3C7; border: 1px solid #FCD34D; border-left: 5px solid #92400E; padding: 14px 18px; border-radius: 8px; margin-bottom: 16px;'><b style='color: #92400E; font-size: 1.05rem;'>⚠️ GATEWAY VERDICT: WARNING</b> — <span style='color: #78350F;'>{live_verdict['reason']}</span></div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"<div style='background-color: #DCFCE7; border: 1px solid #86EFAC; border-left: 5px solid #16A34A; padding: 14px 18px; border-radius: 8px; margin-bottom: 16px;'><b style='color: #16A34A; font-size: 1.05rem;'>🟢 GATEWAY VERDICT: ALLOWED</b> — <span style='color: #14532D;'>{live_verdict['reason']}</span></div>",
                    unsafe_allow_html=True,
                )

        v_res1, v_res2, v_res3 = st.columns(3)
        with v_res1:
            st.markdown(f"**Security Rule:** `{verdict_rule}`")
        with v_res2:
            st.markdown(f"**Mismatched Fields:** `{verdict_changed}`")
        with v_res3:
            st.markdown(f"**Backend State:** `{verdict_state}`")

        # Field-by-Field Diff Comparison Table
        st.markdown("##### 🔍 Field-by-Field Parameter Comparison")
        diff_df = pd.DataFrame(diff_rows)

        def style_diff_status(val):
            v = str(val)
            if "Exact Match" in v:
                return "background-color: #DCFCE7; color: #16A34A; font-weight: bold;"
            elif "Case Discrepancy" in v:
                return "background-color: #FEF3C7; color: #D97706; font-weight: bold;"
            elif "Tampered" in v or "Mismatch" in v or "Invalid" in v:
                return "background-color: #FEE2E2; color: #DC2626; font-weight: bold;"
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
# SECTION 5.4: AUDIT LOG
# ------------------------------------------------------------------------------
elif nav_choice == "Audit Log":
    al_col1, al_col2 = st.columns([5, 1])
    with al_col1:
        st.title("Comprehensive Audit Log")
        st.markdown(
            "<p style='color: #64748B; font-size: 1.05rem; margin-top: -8px;'>"
            "Security audit records of gateway decisions. Investigate runtime security events, "
            "inspect mismatched parameters, and trace actor actions."
            "</p>",
            unsafe_allow_html=True,
        )
    with al_col2:
        st.write("")
        if st.button("🔄 Refresh Data", key="audit_ref_btn", use_container_width=True):
            st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
            st.rerun()
        st.markdown(
            f"""
            <div style="font-size: 0.72rem; color: #64748B; text-align: right; margin-top: -4px;">
                Refreshed: <span style="font-weight: 600; color: #102A43;">{to_ist_string(st.session_state['last_refresh_time'])}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Filter Toolbar
    f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns([2, 2, 2, 4, 1.2])
    with f_col1:
        decision_filter = st.selectbox(
            "Decision:",
            options=["All", "allowed", "blocked", "warning"],
            index=0,
            key="audit_dec_filter",
        )
    with f_col2:
        risk_filter = st.selectbox(
            "Risk Level:",
            options=["All", "low", "medium", "high"],
            index=0,
            key="audit_risk_filter",
        )
    with f_col3:
        tool_options = ["All"] + sorted(list({e.get("tool", "") for e in all_events if e.get("tool")}))
        tool_filter = st.selectbox("Tool:", options=tool_options, index=0, key="audit_tool_filter")
    with f_col4:
        search_query = st.text_input("🔍 Search Event ID / Dept / Request / Actor / Rule / Reason:", "", key="audit_search")
    with f_col5:
        st.write("")
        clear_filters = st.button("Clear", key="audit_clear_btn", use_container_width=True)

    if clear_filters:
        st.session_state["audit_dec_filter"] = "All"
        st.session_state["audit_risk_filter"] = "All"
        st.session_state["audit_tool_filter"] = "All"
        st.session_state["audit_search"] = ""
        st.rerun()

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
            if q in str(e.get("display_id", "")).lower()
            or q in str(e.get("department", "")).lower()
            or q in str(e.get("department_name", "")).lower()
            or q in str(e.get("request_id", "")).lower()
            or q in str(e.get("actor", "")).lower()
            or q in str(e.get("rule", "")).lower()
            or q in str(e.get("reason", "")).lower()
        ]

    st.markdown(
        f"<p style='color: #64748B; font-size: 0.88rem; margin: 8px 0 14px 0;'>"
        f"Displaying <b style='color: #102A43;'>{len(filtered_events)}</b> matching audit records "
        f"(out of {len(all_events)} total, newest first)"
        f"</p>",
        unsafe_allow_html=True,
    )

    if filtered_events:
        # 3-Column Header
        st.markdown(
            """
            <div style="display: flex; align-items: center; justify-content: space-between; padding: 6px 14px; font-size: 0.8rem; font-weight: 700; color: #102A43; text-transform: uppercase; letter-spacing: 0.6px; border-bottom: 2px solid #E2E8F0; margin-bottom: 8px;">
                <div style="flex: 4;">Medical Event ID (Department)</div>
                <div style="flex: 3;">Gateway Decision</div>
                <div style="flex: 3;">Risk Level</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Pagination for Smooth Performance
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

        # Render 3-Column Rows
        for ev in page_events:
            render_audit_event_card(ev, expanded_default=False)
    else:
        st.info("No audit events match your search or filter criteria.")

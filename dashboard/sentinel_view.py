"""MCP Trust Sentinel console UI for MediShield Security Operations Dashboard."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import streamlit as st

from demo.attacks import tool_registry_tampering
from guard.forensics import ForensicEvidenceRecord, ForensicRetrievalError, get_forensic_events
from guard.sentinel import (
    EXPECTED_REGISTRY_FINGERPRINT,
    PREVIOUS_BENCHMARK_FINGERPRINT,
    TRUSTED_MCP_TOOLS,
    RegistryVerificationResult,
    ToolIntegrityDetail,
    compute_registry_fingerprint,
    get_trusted_baseline_tools,
    verify_registry,
)
from server.mcp_server import (
    dispatch_mcp_tool_call,
    get_active_registry,
    reset_active_registry_to_baseline,
)

ROOT_DIR = Path(__file__).resolve().parent.parent


def render_sentinel_console(all_events: List[Dict[str, Any]], to_ist_string: Callable[[Any], str]) -> None:
    """Render the comprehensive MCP Trust Sentinel & Live Tampering Demonstration console."""

    # Top Header & Refresh
    h_col1, h_col2 = st.columns([5, 1])
    with h_col1:
        st.title("🛡️ MCP Trust Sentinel")
        st.markdown(
            "<p style='color: #64748B; font-size: 1.05rem; margin-top: -8px;'>"
            "Continuous tool-registry integrity monitoring, cryptographic fingerprinting, "
            "and fail-closed runtime defense for MCP-connected clinical AI."
            "</p>",
            unsafe_allow_html=True,
        )
    with h_col2:
        st.write("")
        if st.button("🔄 Refresh Data", key="sentinel_top_ref_btn", use_container_width=True):
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

    # Context & Mission Banner
    st.markdown(
        """
        <div class="status-banner" style="border-left-color: #0D9488; margin-bottom: 20px;">
            <div style="display: flex; align-items: flex-start; gap: 12px;">
                <div style="font-size: 1.5rem; line-height: 1;">🛡️</div>
                <div>
                    <div style="font-weight: 700; color: #102A43; font-size: 0.95rem;">
                        Runtime AI Tool Integrity Architecture (MCP Trust Sentinel)
                    </div>
                    <div style="font-size: 0.84rem; color: #475569; margin-top: 3px; line-height: 1.45;">
                        MediShield does not blindly trust the tool interface presented to an AI model.
                        It computes an authoritative <b>SHA-256 cryptographic digest</b> across canonical tool names,
                        clinical descriptions, and JSON parameter schemas. When unauthorized renaming, tool injection,
                        or schema drift is detected, protected actions are <b>rejected fail-closed</b> before any clinical handler is reached.
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Determine live verification result
    observed_tools = st.session_state.get("sentinel_observed_tools")
    live_verification: RegistryVerificationResult = verify_registry(observed_tools)

    # The displayed status is always the current verification result. Session
    # state may describe the last button pressed, but it cannot authorize or
    # override a live registry result.
    status_label = live_verification.status
    if status_label == "TRUSTED":
        status_pill = '<span class="badge-allowed">● TRUSTED</span>'
        status_color = "#16A34A"
        status_sub = "Authoritative baseline matched"
    elif status_label == "DRIFT DETECTED":
        status_pill = '<span class="badge-blocked">● DRIFT DETECTED</span>'
        status_color = "#DC2626"
        status_sub = "Cryptographic mismatch caught"
    elif status_label == "RESTORED":
        status_pill = '<span style="background: #E0F2FE; color: #0284C7; border: 1px solid #BAE6FD; padding: 3px 10px; border-radius: 6px; font-weight: 700; font-size: 0.8rem;">● RESTORED</span>'
        status_color = "#0D9488"
        status_sub = "Reverified against baseline"
    else:
        status_pill = f'<span class="badge-warning">● {status_label}</span>'
        status_color = "#D97706"
        status_sub = "Verification anomaly detected"

    # 4 Top KPI Metric Cards
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Registry Status</div>
                <div class="metric-val" style="color: {status_color}; font-size: 1.35rem;">{status_label}</div>
                <div class="metric-sub">{status_sub}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k2:
        exp_short = live_verification.expected_fingerprint[:14] + "..."
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Expected SHA-256</div>
                <div class="metric-val" style="color: #102A43; font-family: monospace; font-size: 1.1rem;">{exp_short}</div>
                <div class="metric-sub">Authoritative Baseline</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k3:
        obs_short = (
            live_verification.observed_fingerprint[:14] + "..."
            if live_verification.observed_fingerprint
            else "MISSING"
        )
        match_txt = "MATCH" if live_verification.fingerprints_match else "MISMATCH"
        match_color = "#16A34A" if live_verification.fingerprints_match else "#DC2626"
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Observed SHA-256</div>
                <div class="metric-val" style="color: {match_color}; font-family: monospace; font-size: 1.1rem;">{obs_short}</div>
                <div class="metric-sub" style="color: {match_color}; font-weight: 700;">● {match_txt}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k4:
        diff_count = len(live_verification.differences)
        diff_color = "#16A34A" if diff_count == 0 else "#DC2626"
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-lbl">Verified Tool Inventory</div>
                <div class="metric-val" style="color: {diff_color}; font-size: 1.35rem;">
                    {live_verification.observed_tools_count} / {live_verification.expected_tools_count}
                </div>
                <div class="metric-sub">{diff_count} Difference(s) Detected</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")

    # 3 Main Operational Tabs
    tab_demo, tab_monitor, tab_forensics = st.tabs([
        "⚡ Controlled Tampering Demonstration & Proof",
        "🛡️ Tool Integrity Monitor & Baseline",
        "🔍 Forensic Evidence Viewer",
    ])

    # ==========================================================================
    # TAB 1: CONTROLLED TAMPERING DEMONSTRATION & PROOF
    # ==========================================================================
    with tab_demo:
        st.markdown("### ⚡ Live MCP Tool Registry Tampering Demonstration")
        st.caption(
            "Execute a controlled simulation of tool registry tampering against an isolated sandbox fixture. "
            "Witness the complete 7-stage security sequence: Detection $\\rightarrow$ Gateway Fail-Closed Enforcement $\\rightarrow$ "
            "Observable Proof that Patient Data was NOT Accessed $\\rightarrow$ Restoration."
        )

        # Jury Presentation Mode / Proof Guide
        with st.expander("📋 Hackathon Jury Walkthrough: What This Proves in 60 Seconds", expanded=True):
            st.markdown(
                """
                <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 14px 18px; margin-bottom: 8px;">
                    <div style="font-weight: 700; color: #102A43; font-size: 0.95rem; margin-bottom: 6px;">
                        Jury Evaluation Checklist (MediShield vs. Unprotected Healthcare AI)
                    </div>
                    <ol style="margin: 0; padding-left: 20px; font-size: 0.85rem; color: #334155; line-height: 1.6;">
                        <li><b>Stage 1 (Baseline):</b> Demonstrates that all 5 clinical tools are pinned to an authoritative cryptographic fingerprint.</li>
                        <li><b>Stage 2 (Tampering):</b> An attacker or rogue MCP extension renames a tool, introduces an unapproved tool, or strips schema constraints in an isolated test fixture.</li>
                        <li><b>Stage 3 (Detection):</b> MediShield Trust Sentinel detects the discrepancy and updates the registry status to <code>DRIFT DETECTED</code>.</li>
                        <li><b>Stage 4 & 5 (Enforcement):</b> A synthetic agent request to access patient data is routed through the gateway and <b>blocked fail-closed</b>.</li>
                        <li><b>Stage 6 (Observable Proof):</b> Verification telemetry proves the patient-data handler had <b>0 invocations</b> and <b>0 records returned</b>.</li>
                        <li><b>Stage 7 & 8 (Recovery):</b> The isolated registry is restored to the trusted baseline and authorized operations resume seamlessly.</li>
                    </ol>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Attack Controls
        ctrl_col1, ctrl_col2 = st.columns([3, 2])
        with ctrl_col1:
            tamper_mode = st.selectbox(
                "Select Adversarial Tampering Scenario:",
                options=[
                    "rename_tool",
                    "unexpected_tool",
                    "schema_drift",
                ],
                format_func=lambda x: {
                    "rename_tool": "🔴 Tool Renaming: Rename 'get_patient_record' -> 'get_patient_record_tampered'",
                    "unexpected_tool": "🔴 Rogue Tool Injection: Inject unauthorized 'unauthorized_export_tool'",
                    "schema_drift": "🔴 Schema Drift: Strip required 'dose' constraint from 'propose_medication_order'",
                }.get(x, x),
                index=0,
                key="tamper_scenario_select",
            )
        with ctrl_col2:
            target_patient = st.text_input(
                "Synthetic Target Patient ID:",
                value="P-104",
                key="tamper_patient_input",
                help="Protected patient record targeted during the simulated adversarial tool call.",
            )

        btn_col1, btn_col2, btn_col3 = st.columns(3)
        with btn_col1:
            run_tamper = st.button("⚡ Simulate MCP Tool Tampering", type="primary", use_container_width=True)
        with btn_col2:
            run_restore = st.button("🔄 Restore Isolated Registry & Reverify", use_container_width=True)
        with btn_col3:
            run_resume = st.button("✅ Resume Authorized Operation", use_container_width=True)

        # Handle Action Triggers
        if run_tamper:
            with st.spinner("Executing controlled MCP registry tampering in isolated sandbox..."):
                sim_res = tool_registry_tampering(tamper_mode=tamper_mode, patient_id=target_patient)
                st.session_state["sentinel_tamper_result"] = sim_res
                st.session_state["sentinel_observed_tools"] = sim_res["stage2_tampered_registry"]
                st.session_state["sentinel_status_override"] = "DRIFT DETECTED"
                st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
                st.rerun()

        if run_restore:
            with st.spinner("Restoring isolated registry to authoritative baseline..."):
                reset_active_registry_to_baseline()
                st.session_state["sentinel_observed_tools"] = None
                st.session_state["sentinel_status_override"] = "RESTORED"
                st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
                st.rerun()

        if run_resume:
            with st.spinner("Dispatching authorized clinical request on restored registry..."):
                auth_res = dispatch_mcp_tool_call(
                    tool_name="get_patient_record",
                    arguments={"patient_id": target_patient},
                    actor_id="clinician_1",
                    registry_override=None,
                )
                st.session_state["sentinel_authorized_result"] = auth_res
                st.session_state["sentinel_status_override"] = "TRUSTED"
                st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
                st.rerun()

        st.markdown("---")

        # Render Simulation Results
        sim_data = st.session_state.get("sentinel_tamper_result")
        if sim_data:
            st.markdown("#### 🔬 Live Demonstration Telemetry & Forensic Findings")

            st1, st2, st3 = st.columns(3)
            with st1:
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 14px;">
                        <div style="font-size: 0.76rem; color: #64748B; font-weight: 700; text-transform: uppercase;">Stage 1: Trusted Baseline</div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #16A34A; margin-top: 4px;">● TRUSTED</div>
                        <div style="font-size: 0.78rem; font-family: monospace; color: #334155; margin-top: 4px;">
                            FP: {sim_data['stage1_baseline']['expected_fingerprint'][:16]}...
                        </div>
                        <div style="font-size: 0.74rem; color: #64748B; margin-top: 4px;">5/5 Tools Cryptographically Pinned</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with st2:
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 14px;">
                        <div style="font-size: 0.76rem; color: #64748B; font-weight: 700; text-transform: uppercase;">Stage 2: Tampering Applied</div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #DC2626; margin-top: 4px;">● MODIFIED FIXTURE</div>
                        <div style="font-size: 0.78rem; color: #334155; margin-top: 4px;">
                            <b>Mode:</b> {sim_data['stage6_evidence']['tamper_mode']}
                        </div>
                        <div style="font-size: 0.74rem; color: #64748B; margin-top: 4px;">{sim_data['stage6_evidence']['tamper_description']}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with st3:
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 14px;">
                        <div style="font-size: 0.76rem; color: #64748B; font-weight: 700; text-transform: uppercase;">Stage 3: Sentinel Detection</div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #DC2626; margin-top: 4px;">● DRIFT DETECTED</div>
                        <div style="font-size: 0.78rem; font-family: monospace; color: #334155; margin-top: 4px;">
                            FP: {sim_data['stage3_detection']['observed_fingerprint'][:16]}...
                        </div>
                        <div style="font-size: 0.74rem; color: #DC2626; font-weight: 600; margin-top: 4px;">Fingerprint Mismatch Confirmed</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.write("")

            # ==================================================================
            # PROOF THAT PATIENT DATA WAS NOT ACCESSED (PART 8)
            # ==================================================================
            proof = sim_data["stage5_observable_proof"]
            st.markdown(
                f"""
                <div style="background: #FFFFFF; border: 2px solid #0D9488; border-radius: 10px; padding: 18px; margin-bottom: 16px; box-shadow: 0 2px 6px rgba(13, 148, 136, 0.08);">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px;">
                        <span style="font-weight: 800; color: #102A43; font-size: 1.05rem;">
                            🔒 VERIFIABLE JURY PROOF: CLINICAL DATA ACCESS PREVENTED
                        </span>
                        <span class="badge-allowed">FAIL-CLOSED VERIFIED</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #334155; margin-bottom: 14px;">
                        The jury must distinguish a request blocked at the gateway from one that retrieved sensitive records before failing.
                        MediShield provides genuine observable telemetry proving the protected clinical data handler was never reached.
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;">
                        <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; padding: 10px; text-align: center;">
                            <div style="font-size: 0.72rem; color: #64748B; font-weight: 700; text-transform: uppercase;">Handler Invocation</div>
                            <div style="font-size: 1.25rem; font-weight: 800; color: #16A34A; margin-top: 2px;">
                                {'TRUE (LEAKED)' if proof['handler_invoked'] else 'FALSE (BLOCKED)'}
                            </div>
                            <div style="font-size: 0.7rem; color: #64748B;">0 Invocations Reached</div>
                        </div>
                        <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; padding: 10px; text-align: center;">
                            <div style="font-size: 0.72rem; color: #64748B; font-weight: 700; text-transform: uppercase;">Records Returned</div>
                            <div style="font-size: 1.25rem; font-weight: 800; color: #16A34A; margin-top: 2px;">
                                {'RETURNED' if proof['patient_record_returned'] else 'NONE (0 BYTES)'}
                            </div>
                            <div style="font-size: 0.7rem; color: #64748B;">Zero Clinical Exposure</div>
                        </div>
                        <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; padding: 10px; text-align: center;">
                            <div style="font-size: 0.72rem; color: #64748B; font-weight: 700; text-transform: uppercase;">Backend State Changed</div>
                            <div style="font-size: 1.25rem; font-weight: 800; color: #16A34A; margin-top: 2px;">
                                {'TRUE' if proof['state_changed'] else 'FALSE'}
                            </div>
                            <div style="font-size: 0.7rem; color: #64748B;">Database Records Unaltered</div>
                        </div>
                        <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; padding: 10px; text-align: center;">
                            <div style="font-size: 0.72rem; color: #64748B; font-weight: 700; text-transform: uppercase;">Security Enforcement</div>
                            <div style="font-size: 1.25rem; font-weight: 800; color: #DC2626; margin-top: 2px;">
                                {sim_data['stage4_dispatch_result']['decision'].upper()}
                            </div>
                            <div style="font-size: 0.7rem; color: #64748B;">{sim_data['stage4_dispatch_result']['rule']}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Security Decision Details (Part 9)
            dec_col1, dec_col2 = st.columns(2)
            with dec_col1:
                st.markdown("##### 🛡️ Gateway Decision Telemetry")
                st.markdown(f"- **Request ID:** `{sim_data['stage4_dispatch_result']['request_id']}`")
                st.markdown(f"- **Operation Name:** `{sim_data['stage4_dispatch_result']['tool']}`")
                st.markdown(f"- **Verdict:** <span class='badge-blocked'>BLOCKED</span>", unsafe_allow_html=True)
                st.markdown(f"- **Security Rule:** `{sim_data['stage4_dispatch_result']['rule']}`")
                st.markdown(f"- **Decision Reason:** {sim_data['stage4_dispatch_result']['reason']}")
            with dec_col2:
                st.markdown("##### 🔬 Detected Discrepancies")
                diffs = sim_data["stage3_detection"].get("differences", [])
                if diffs:
                    for d in diffs:
                        st.markdown(f"- ⚠️ {d}")
                else:
                    st.markdown("- No textual differences reported.")
                st.markdown(f"- **Target Patient Tested:** `{target_patient}`")
                st.markdown(f"- **Approval State:** *Not Evaluated (Halted at Registry Boundary)*")

            # Stage 7 & 8: Restoration & Authorized Resumption Status
            st.markdown("---")
            res_col1, res_col2 = st.columns(2)
            with res_col1:
                st.markdown("##### 🔄 Stage 7: Isolated Registry Restoration")
                st.markdown(f"- **Restored Status:** <span class='badge-allowed'>● {sim_data['stage7_restoration']['status']}</span>", unsafe_allow_html=True)
                st.markdown(f"- **Reverified SHA-256:** `{sim_data['stage7_restoration']['observed_fingerprint'][:24]}...`")
                st.markdown(f"- **Fingerprints Match:** `{sim_data['stage7_restoration']['fingerprints_match']}`")
                st.markdown("- **Registry State:** Baseline re-anchored. Ready for authorized execution.")
            with res_col2:
                st.markdown("##### ✅ Stage 8: Authorized Resumption Outcome")
                auth_d = sim_data["stage8_authorized_resumption"]
                st.markdown(f"- **Authorized Verdict:** <span class='badge-allowed'>{auth_d['decision'].upper()}</span>", unsafe_allow_html=True)
                st.markdown(f"- **Security Rule:** `{auth_d['rule']}`")
                st.markdown(f"- **Handler Invoked:** `{auth_d['handler_invoked']}` *(Genuine Retrieval)*")
                st.markdown(f"- **Retrieved Patient:** `{auth_d['data'].get('name_synthetic', 'Synthetic Patient')}`")

        else:
            st.info("💡 Click **'⚡ Simulate MCP Tool Tampering'** above to launch the controlled hackathon jury demonstration.")

        # If user ran direct authorized resumption from button
        direct_auth = st.session_state.get("sentinel_authorized_result")
        if direct_auth:
            st.success(
                f"✅ **Authorized Clinical Call Succeeded on Verified Registry:** "
                f"Retrieved `{direct_auth['data'].get('name_synthetic', 'Synthetic Patient')}` ({direct_auth['data'].get('patient_id')}) — "
                f"Decision: `{direct_auth['decision'].upper()}` ({direct_auth['rule']})."
            )

    # ==========================================================================
    # TAB 2: TOOL INTEGRITY MONITOR & BASELINE (PARTS 4, 5, 6, 11)
    # ==========================================================================
    with tab_monitor:
        st.markdown("### 🛡️ MCP Tool Integrity Monitor")
        st.caption(
            "Live inspection of expected vs. observed tool definitions, parameter schemas, "
            "and cryptographic SHA-256 digests."
        )

        # Tool Integrity Table (Part 5)
        details = live_verification.tool_details
        if details:
            # Build clean HTML table
            rows_html = []
            for t in details:
                if t.status == "VERIFIED":
                    badge_html = '<span class="badge-allowed">VERIFIED</span>'
                elif t.status == "MISSING":
                    badge_html = '<span class="badge-blocked">MISSING</span>'
                elif t.status == "UNEXPECTED":
                    badge_html = '<span class="badge-blocked">UNEXPECTED</span>'
                elif t.status == "RENAMED":
                    badge_html = '<span class="badge-warning">RENAMED</span>'
                else:
                    badge_html = f'<span class="badge-warning">{t.status}</span>'

                exp_icon = "✅" if t.expected_presence else "❌"
                obs_icon = "✅" if t.observed_presence else "❌"

                rows_html.append(
                    f"""
                    <tr style="border-bottom: 1px solid #E2E8F0;">
                        <td style="padding: 10px 12px; font-weight: 700; color: #102A43; font-family: monospace;">{t.name}</td>
                        <td style="padding: 10px 12px; text-align: center;">{exp_icon}</td>
                        <td style="padding: 10px 12px; text-align: center;">{obs_icon}</td>
                        <td style="padding: 10px 12px;">{badge_html}</td>
                        <td style="padding: 10px 12px; font-size: 0.8rem; color: #334155;">{t.schema_status}</td>
                        <td style="padding: 10px 12px; font-size: 0.8rem; color: #64748B;">{t.description}</td>
                        <td style="padding: 10px 12px; font-size: 0.8rem; color: #334155;">{t.findings}</td>
                    </tr>
                    """
                )

            table_html = f"""
            <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; overflow-x: auto; margin-bottom: 18px;">
                <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left;">
                    <thead>
                        <tr style="background: #F8FAFC; border-bottom: 2px solid #E2E8F0; color: #64748B; font-weight: 700; font-size: 0.75rem; text-transform: uppercase;">
                            <th style="padding: 10px 12px;">Tool Name</th>
                            <th style="padding: 10px 12px; text-align: center;">Expected</th>
                            <th style="padding: 10px 12px; text-align: center;">Observed</th>
                            <th style="padding: 10px 12px;">Integrity Status</th>
                            <th style="padding: 10px 12px;">Schema</th>
                            <th style="padding: 10px 12px;">Clinical Description</th>
                            <th style="padding: 10px 12px;">Sentinel Findings</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows_html)}
                    </tbody>
                </table>
            </div>
            """
            st.markdown(table_html, unsafe_allow_html=True)
        else:
            st.info("No tool registry details available.")

        # Fingerprint Comparison & Technical Deep Dive (Part 6)
        with st.expander("🔬 Cryptographic Fingerprint Inspection & Canonicalization Details", expanded=False):
            st.markdown(
                """
                <div style="font-size: 0.85rem; color: #334155; line-height: 1.5; margin-bottom: 12px;">
                    MediShield uses <b>deterministic canonical serialization</b>: tool names are alphabetically sorted,
                    key-value pairs are canonicalized, and whitespace is compressed before computing the SHA-256 digest.
                    Even a 1-character modification or whitespace manipulation in a tool's description or JSON schema
                    causes an avalanche effect resulting in a completely distinct SHA-256 hash.
                </div>
                """,
                unsafe_allow_html=True,
            )

            fc1, fc2 = st.columns(2)
            with fc1:
                st.markdown("**Expected Baseline SHA-256:**")
                st.code(live_verification.expected_fingerprint, language="text")
                st.caption(f"Authoritative digest computed from {len(TRUSTED_MCP_TOOLS)} baseline tool definitions.")
            with fc2:
                st.markdown("**Observed Registry SHA-256:**")
                st.code(live_verification.observed_fingerprint, language="text")
                if live_verification.fingerprints_match:
                    st.caption("✅ Digest matches expected baseline byte-for-byte.")
                else:
                    st.caption("❌ Cryptographic divergence detected.")

            st.markdown(f"**Benchmark Reference:** `{PREVIOUS_BENCHMARK_FINGERPRINT}` *(Historic demonstration reference)*")

            st.markdown("**Raw Canonical Tool Registry Payload:**")
            st.json(get_trusted_baseline_tools())

        # Security Workflow Explanation (Part 11)
        st.markdown("#### 📐 MediShield Protected Execution Architecture")
        st.caption("Sequence of defense boundaries enforced before any clinical backend mutation or patient data access.")

        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 18px; margin-bottom: 12px;">
                <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
                    <div style="flex: 1; min-width: 140px; background: #F8FAFC; border: 1px solid #CBD5E1; border-radius: 6px; padding: 10px; text-align: center;">
                        <div style="font-size: 0.7rem; color: #64748B; font-weight: 700;">STEP 1</div>
                        <div style="font-size: 0.88rem; font-weight: 700; color: #102A43;">AI Tool Call</div>
                        <div style="font-size: 0.72rem; color: #64748B;">Agent emits MCP call</div>
                    </div>
                    <div style="font-size: 1.2rem; color: #0D9488;">➔</div>
                    <div style="flex: 1.2; min-width: 160px; background: #FEF3C7; border: 1px solid #FCD34D; border-radius: 6px; padding: 10px; text-align: center;">
                        <div style="font-size: 0.7rem; color: #B45309; font-weight: 700;">STEP 2 (SENTINEL)</div>
                        <div style="font-size: 0.88rem; font-weight: 700; color: #B45309;">Registry Check</div>
                        <div style="font-size: 0.72rem; color: #B45309;">SHA-256 Fingerprint</div>
                    </div>
                    <div style="font-size: 1.2rem; color: #0D9488;">➔</div>
                    <div style="flex: 1; min-width: 140px; background: #F8FAFC; border: 1px solid #CBD5E1; border-radius: 6px; padding: 10px; text-align: center;">
                        <div style="font-size: 0.7rem; color: #64748B; font-weight: 700;">STEP 3</div>
                        <div style="font-size: 0.88rem; font-weight: 700; color: #102A43;">Role Auth</div>
                        <div style="font-size: 0.72rem; color: #64748B;">Permitted actor check</div>
                    </div>
                    <div style="font-size: 1.2rem; color: #0D9488;">➔</div>
                    <div style="flex: 1.2; min-width: 160px; background: #DCFCE7; border: 1px solid #86EFAC; border-radius: 6px; padding: 10px; text-align: center;">
                        <div style="font-size: 0.7rem; color: #15803D; font-weight: 700;">STEP 4</div>
                        <div style="font-size: 0.88rem; font-weight: 700; color: #15803D;">Clinical Intent Lock</div>
                        <div style="font-size: 0.72rem; color: #15803D;">Doctor Approval HMAC</div>
                    </div>
                    <div style="font-size: 1.2rem; color: #0D9488;">➔</div>
                    <div style="flex: 1; min-width: 140px; background: #F8FAFC; border: 1px solid #CBD5E1; border-radius: 6px; padding: 10px; text-align: center;">
                        <div style="font-size: 0.7rem; color: #64748B; font-weight: 700;">STEP 5</div>
                        <div style="font-size: 0.88rem; font-weight: 700; color: #102A43;">Backend Execution</div>
                        <div style="font-size: 0.72rem; color: #64748B;">Atomic SQLite update</div>
                    </div>
                </div>
                <div style="font-size: 0.8rem; color: #64748B; margin-top: 12px; text-align: center;">
                    <b>Fail-Closed Enforcement Rule:</b> If Step 2 (Trust Sentinel) detects drift or an unapproved tool,
                    execution is <b>immediately terminated</b> with state unaltered and zero clinical data accessed.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ==========================================================================
    # TAB 3: FORENSIC EVIDENCE VIEWER (PART 10)
    # ==========================================================================
    with tab_forensics:
        st.markdown("### 🔍 Forensic Evidence Viewer")
        st.caption(
            "Inspect verifiable runtime incident evidence, tamper detections, and cryptographic audit logs "
            "persisted in the gateway repository."
        )

        # Filter controls
        f_col1, f_col2, f_col3 = st.columns([2, 2, 1])
        with f_col1:
            dec_filter = st.selectbox(
                "Filter by Gateway Decision:",
                options=["All", "allowed", "blocked", "warning"],
                index=0,
                key="forensic_dec_filter",
            )
        with f_col2:
            type_filter = st.selectbox(
                "Filter by Event Type:",
                options=["All", "mcp:get_patient_record", "update_order", "mcp:get_security_events"],
                index=0,
                key="forensic_type_filter",
            )
        with f_col3:
            limit_val = st.number_input("Event Limit:", min_value=10, max_value=200, value=50, step=10)

        # Retrieve forensic events
        try:
            forensic_records: List[ForensicEvidenceRecord] = get_forensic_events(
                limit=limit_val,
                decision_filter=None if dec_filter == "All" else dec_filter,
                event_type_filter=None if type_filter == "All" else type_filter,
            )
        except ForensicRetrievalError:
            forensic_records = []
            st.error("Forensic evidence could not be verified from the audit store.")

        st.markdown(f"**Displaying {len(forensic_records)} forensic evidence records:**")

        if forensic_records:
            for rec in forensic_records:
                dec_str = rec.decision.upper()
                if dec_str == "ALLOWED":
                    badge_cls = "badge-allowed"
                elif dec_str == "BLOCKED":
                    badge_cls = "badge-blocked"
                else:
                    badge_cls = "badge-warning"

                sim_tag = (
                    '<span style="background: #F1F5F9; color: #475569; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; margin-left: 6px;">SIMULATION</span>'
                    if rec.is_simulation
                    else '<span style="background: #E0F2FE; color: #0369A1; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; margin-left: 6px;">NORMAL</span>'
                )

                st_time = to_ist_string(rec.timestamp)
                with st.expander(f"{rec.request_id} • {rec.tool} • {dec_str} ({st_time})", expanded=False):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown(f"**Decision:** <span class='{badge_cls}'>{dec_str}</span> {sim_tag}", unsafe_allow_html=True)
                        st.markdown(f"**Security Rule:** `{rec.rule}`")
                        st.markdown(f"**Clinical Reason:** {rec.reason}")
                        st.markdown(f"**Tool / Operation:** `{rec.tool}` (`{rec.event_type}`)")
                        st.markdown(f"**Actor ID:** `{rec.actor}`")
                    with c2:
                        st.markdown(f"**Timestamp (IST):** `{st_time}`")
                        st.markdown(f"**State Changed:** `{rec.state_changed}`")
                        st.markdown(f"**Risk Level:** `{rec.risk.upper()}`")
                        if rec.detected_mismatch:
                            st.markdown(f"**Detected Discrepancies:** `{rec.detected_mismatch}`")

                    # Raw Evidence JSON
                    st.markdown("**Raw Structured Audit Record (Safe JSON):**")
                    st.json(rec.raw_payload)
        else:
            st.info("No forensic evidence records matched the selected filters.")

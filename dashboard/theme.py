"""
MediShield Enterprise Design System & Reusable UI Component Library
===================================================================
A unified, state-of-the-art B2B healthcare security interface system.
Strictly adheres to the MediShield Enterprise Palette:
- Midnight Navy:  #101828 (Primary brand & sidebar navigation)
- Dark Slate:     #1D2939 (Secondary dark surfaces & cards)
- Medical Teal:   #0F9D8A (Signature brand accent & approved actions)
- Pale Mint:      #E8F7F3 (Subtle positive-state backgrounds)
- Warm Off-White: #F7F8FA (Main application canvas background)
- Pure White:     #FFFFFF (Cards, panels, content surfaces)
- Slate Grey:     #667085 (Secondary metadata & labels)
- Border Grey:    #E4E7EC (Restrained dividers and borders)
- Warning Amber:  #B54708 (Warnings and pending reviews)
- Alert Red:      #D92D20 (Blocked threats, failures, critical alerts)
- Enterprise Blue:#175CD3 (Informational and neutral system states)
"""

from __future__ import annotations

import base64
import html
from typing import Any, Dict, List, Optional, Tuple
import streamlit as st


# ==============================================================================
# SECTION 1: Brand Assets & SVG Definitions
# ==============================================================================

# Distinctive MediShield Brand Mark (Shield + Subtle Clinical Cross)
MEDISHIELD_SHIELD_SVG = """
<svg width="32" height="32" viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align: middle;">
  <defs>
    <linearGradient id="shieldGrad" x1="4" y1="4" x2="32" y2="32" gradientUnits="userSpaceOnUse">
      <stop stop-color="#1D2939"/>
      <stop offset="1" stop-color="#101828"/>
    </linearGradient>
    <linearGradient id="tealGrad" x1="10" y1="10" x2="26" y2="26" gradientUnits="userSpaceOnUse">
      <stop stop-color="#0F9D8A"/>
      <stop offset="1" stop-color="#077A6A"/>
    </linearGradient>
  </defs>
  <path d="M18 3L5 7.8V16.8C5 25.1 10.6 32.8 18 34.5C25.4 32.8 31 25.1 31 16.8V7.8L18 3Z" fill="url(#shieldGrad)" stroke="#0F9D8A" stroke-width="2" stroke-linejoin="round"/>
  <path d="M18 6.5L7.5 10.3V16.8C7.5 23.5 12 29.8 18 31.3C24 29.8 28.5 23.5 28.5 16.8V10.3L18 6.5Z" stroke="#0F9D8A" stroke-width="1" stroke-opacity="0.35"/>
  <path d="M18 11V25M11 18H25" stroke="url(#tealGrad)" stroke-width="2.8" stroke-linecap="round"/>
  <circle cx="18" cy="18" r="3.2" fill="#0F9D8A"/>
  <circle cx="18" cy="18" r="1.5" fill="#E8F7F3"/>
</svg>
"""

MEDISHIELD_FAVICON_SVG = """
<svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M16 2L4 6.5V14.5C4 21.8 9.1 28.6 16 30C22.9 28.6 28 21.8 28 14.5V6.5L16 2Z" fill="#101828" stroke="#0F9D8A" stroke-width="2.5" stroke-linejoin="round"/>
  <path d="M16 9V23M9 16H23" stroke="#0F9D8A" stroke-width="2.8" stroke-linecap="round"/>
  <circle cx="16" cy="16" r="2.5" fill="#E8F7F3"/>
</svg>
"""

# Lucide-style Outline SVG Icons (stroke-width: 1.8, stroke: currentColor, 18x18 viewBox)
LUCIDE_ICONS: Dict[str, str] = {
    "overview": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>""",
    "patient": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>""",
    "approval": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="8" height="4" x="8" y="2" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="m9 14 2 2 4-4"/></svg>""",
    "intent": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>""",
    "sentinel": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>""",
    "vault": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/><rect width="8" height="6" x="8" y="12" rx="1"/><path d="M10 12v-2a2 2 0 1 1 4 0v2"/></svg>""",
    "lab": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 2v7.31"/><path d="M14 9.3V2"/><path d="M8.5 2h7"/><path d="M14 9.3a6.5 6.5 0 1 1-4 0"/><path d="M5.52 16h12.96"/></svg>""",
    "audit": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>""",
    "check": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>""",
    "blocked": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><line x1="9.5" x2="14.5" y1="9.5" y2="14.5"/><line x1="14.5" x2="9.5" y1="9.5" y2="14.5"/></svg>""",
    "warning": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>""",
    "info": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="16" y2="12"/><line x1="12" x2="12.01" y1="8" y2="8"/></svg>""",
    "database": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>""",
    "lock": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>""",
    "refresh": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 21h5v-5"/></svg>""",
    "arrow-right": """<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>""",
}


def get_icon_svg(name: str, color: Optional[str] = None, size: int = 18) -> str:
    """Return inline SVG icon markup with optional color/size override."""
    raw = LUCIDE_ICONS.get(name, LUCIDE_ICONS["info"])
    if color:
        raw = raw.replace('stroke="currentColor"', f'stroke="{color}"')
    if size != 18:
        raw = raw.replace('width="18"', f'width="{size}"').replace('height="18"', f'height="{size}"')
    return raw


# ==============================================================================
# SECTION 2: Global Enterprise CSS Stylesheet
# ==============================================================================

ENTERPRISE_CSS = """
<style>
/* --------------------------------------------------------------------------
   MediShield Enterprise B2B Healthcare Security Theme
   Primary:   #101828 (Midnight Navy)
   Secondary: #1D2939 (Dark Slate)
   Accent:    #0F9D8A (Medical Teal)
   Surface:   #FFFFFF (Pure White)
   Canvas:    #F7F8FA (Warm Off-White)
   Border:    #E4E7EC (Restrained Border Grey)
   Text:      #101828 (Primary), #667085 (Secondary)
   -------------------------------------------------------------------------- */

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {
    --ms-midnight: #101828;
    --ms-slate-dark: #1D2939;
    --ms-teal: #0F9D8A;
    --ms-teal-hover: #0C8070;
    --ms-mint-light: #E8F7F3;
    --ms-offwhite: #F7F8FA;
    --ms-white: #FFFFFF;
    --ms-slate: #667085;
    --ms-slate-light: #98A2B3;
    --ms-border: #E4E7EC;
    --ms-border-focus: #0F9D8A;
    --ms-amber: #B54708;
    --ms-amber-bg: #FEF6EE;
    --ms-amber-border: #FEDF89;
    --ms-red: #D92D20;
    --ms-red-bg: #FEF3F2;
    --ms-red-border: #FECDCA;
    --ms-blue: #175CD3;
    --ms-blue-bg: #EFF8FF;
    --ms-blue-border: #B2DDFF;
    --ms-green: #079455;
    --ms-green-bg: #EDFDF7;
    --ms-green-border: #A6F4C5;
    --ms-radius: 8px;
    --ms-shadow-sm: 0 1px 2px 0 rgba(16, 24, 40, 0.05);
    --ms-shadow-md: 0 4px 8px -2px rgba(16, 24, 40, 0.08), 0 2px 4px -2px rgba(16, 24, 40, 0.04);
}

/* Global Typography & Canvas */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif !important;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

.stApp {
    background-color: var(--ms-offwhite) !important;
    color: var(--ms-midnight) !important;
}

/* Content Container Width & Padding */
.block-container {
    padding-top: 1.5rem !important;
    padding-bottom: 3.5rem !important;
    padding-left: 2.2rem !important;
    padding-right: 2.2rem !important;
    max-width: 1380px !important;
}

/* Headings Hierarchy */
h1, h2, h3, h4, h5, h6 {
    color: var(--ms-midnight) !important;
    font-weight: 700 !important;
    letter-spacing: -0.025em !important;
    margin-bottom: 0.5rem !important;
}

h1 {
    font-size: 1.85rem !important;
    font-weight: 800 !important;
}

h2 {
    font-size: 1.45rem !important;
}

h3 {
    font-size: 1.2rem !important;
}

p, span, label {
    color: var(--ms-midnight);
}

/* --------------------------------------------------------------------------
   SIDEBAR: Deep Midnight Navy Shell (#101828)
   -------------------------------------------------------------------------- */
section[data-testid="stSidebar"],
[data-testid="stSidebar"],
[data-testid="stSidebarContent"],
[data-testid="stSidebarUserContent"],
div[data-testid="stSidebarHeader"] {
    background-color: var(--ms-midnight) !important;
    background: var(--ms-midnight) !important;
    border-right: 1px solid var(--ms-slate-dark) !important;
}

section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] .stMarkdown p {
    color: #D0D5DD !important;
}

section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {
    color: #FFFFFF !important;
}

/* Sidebar Selectboxes */
section[data-testid="stSidebar"] .stSelectbox > div > div {
    background-color: var(--ms-slate-dark) !important;
    border: 1px solid #344054 !important;
    border-radius: 6px !important;
    color: #F2F4F7 !important;
}

section[data-testid="stSidebar"] .stSelectbox label {
    color: #98A2B3 !important;
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
}

/* Sidebar Radio Navigation */
section[data-testid="stSidebar"] div[role="radiogroup"] {
    gap: 3px !important;
    margin-top: 4px !important;
}

/* Hide default radio circle for native SaaS navigation feel */
section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:first-child {
    display: none !important;
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label input[type="radio"] {
    display: none !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label {
    padding: 9px 12px !important;
    border-radius: 6px !important;
    margin-bottom: 2px !important;
    transition: all 0.15s ease-in-out !important;
    background-color: transparent !important;
    border-left: 3px solid transparent !important;
    cursor: pointer !important;
    display: flex !important;
    align-items: center !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
    background-color: rgba(255, 255, 255, 0.06) !important;
    color: #FFFFFF !important;
}

/* Active Navigation Item */
section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"],
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
    background-color: rgba(15, 157, 138, 0.16) !important;
    border-left: 3px solid var(--ms-teal) !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label span,
section[data-testid="stSidebar"] div[role="radiogroup"] > label p {
    font-size: 0.88rem !important;
    font-weight: 500 !important;
    margin: 0 !important;
    padding: 0 !important;
    color: #D0D5DD !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] span,
section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] p,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) span,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) p {
    color: #FFFFFF !important;
    font-weight: 600 !important;
}

/* Outline Navigation Icons via CSS pseudo-elements (targets both p and span) */
section[data-testid="stSidebar"] div[role="radiogroup"] > label span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label p::before {
    content: "";
    display: inline-block;
    width: 17px;
    height: 17px;
    margin-right: 10px;
    vertical-align: -3px;
    background-repeat: no-repeat;
    background-size: 17px 17px;
    opacity: 0.75;
    transition: opacity 0.15s ease;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover p::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) p::before {
    opacity: 1;
}

/* 1. Overview */
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(1) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(1) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%2398A2B3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect width='7' height='9' x='3' y='3' rx='1'/%3E%3Crect width='7' height='5' x='14' y='3' rx='1'/%3E%3Crect width='7' height='9' x='14' y='12' rx='1'/%3E%3Crect width='7' height='5' x='3' y='16' rx='1'/%3E%3C/svg%3E");
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(1):has(input:checked) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(1):has(input:checked) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%230F9D8A' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect width='7' height='9' x='3' y='3' rx='1'/%3E%3Crect width='7' height='5' x='14' y='3' rx='1'/%3E%3Crect width='7' height='9' x='14' y='12' rx='1'/%3E%3Crect width='7' height='5' x='3' y='16' rx='1'/%3E%3C/svg%3E");
}

/* 2. Patient Directory & EHR */
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(2) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(2) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%2398A2B3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2'/%3E%3Ccircle cx='9' cy='7' r='4'/%3E%3Cpath d='M22 21v-2a4 4 0 0 0-3-3.87'/%3E%3Cpath d='M16 3.13a4 4 0 0 1 0 7.75'/%3E%3C/svg%3E");
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(2):has(input:checked) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(2):has(input:checked) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%230F9D8A' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2'/%3E%3Ccircle cx='9' cy='7' r='4'/%3E%3Cpath d='M22 21v-2a4 4 0 0 0-3-3.87'/%3E%3Cpath d='M16 3.13a4 4 0 0 1 0 7.75'/%3E%3C/svg%3E");
}

/* 3. Clinician Approval Hub */
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(3) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(3) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%2398A2B3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect width='8' height='4' x='8' y='2' rx='1' ry='1'/%3E%3Cpath d='M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2'/%3E%3Cpath d='m9 14 2 2 4-4'/%3E%3C/svg%3E");
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(3):has(input:checked) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(3):has(input:checked) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%230F9D8A' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect width='8' height='4' x='8' y='2' rx='1' ry='1'/%3E%3Cpath d='M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2'/%3E%3Cpath d='m9 14 2 2 4-4'/%3E%3C/svg%3E");
}

/* 4. Intent Lock Verification */
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(4) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(4) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%2398A2B3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='7.5' cy='15.5' r='5.5'/%3E%3Cpath d='m21 2-9.6 9.6'/%3E%3Cpath d='m15.5 7.5 3 3L22 7l-3-3'/%3E%3C/svg%3E");
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(4):has(input:checked) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(4):has(input:checked) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%230F9D8A' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='7.5' cy='15.5' r='5.5'/%3E%3Cpath d='m21 2-9.6 9.6'/%3E%3Cpath d='m15.5 7.5 3 3L22 7l-3-3'/%3E%3C/svg%3E");
}

/* 5. MCP Trust Sentinel */
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(5) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(5) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%2398A2B3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10'/%3E%3Cpath d='m9 12 2 2 4-4'/%3E%3C/svg%3E");
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(5):has(input:checked) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(5):has(input:checked) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%230F9D8A' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10'/%3E%3Cpath d='m9 12 2 2 4-4'/%3E%3C/svg%3E");
}

/* 6. Secure Document Vault */
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(6) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(6) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%2398A2B3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z'/%3E%3Crect width='8' height='6' x='8' y='12' rx='1'/%3E%3Cpath d='M10 12v-2a2 2 0 1 1 4 0v2'/%3E%3C/svg%3E");
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(6):has(input:checked) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(6):has(input:checked) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%230F9D8A' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z'/%3E%3Crect width='8' height='6' x='8' y='12' rx='1'/%3E%3Cpath d='M10 12v-2a2 2 0 1 1 4 0v2'/%3E%3C/svg%3E");
}

/* 7. Security Test Lab */
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(7) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(7) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%2398A2B3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M10 2v7.31'/%3E%3Cpath d='M14 9.3V2'/%3E%3Cpath d='M8.5 2h7'/%3E%3Cpath d='M14 9.3a6.5 6.5 0 1 1-4 0'/%3E%3Cpath d='M5.52 16h12.96'/%3E%3C/svg%3E");
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(7):has(input:checked) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(7):has(input:checked) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%230F9D8A' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M10 2v7.31'/%3E%3Cpath d='M14 9.3V2'/%3E%3Cpath d='M8.5 2h7'/%3E%3Cpath d='M14 9.3a6.5 6.5 0 1 1-4 0'/%3E%3Cpath d='M5.52 16h12.96'/%3E%3C/svg%3E");
}

/* 8. Audit Log & Forensic Ledger */
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(8) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(8) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%2398A2B3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z'/%3E%3Cpolyline points='17 21 17 13 7 13 7 21'/%3E%3Cpolyline points='7 3 7 8 15 8'/%3E%3C/svg%3E");
}
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(8):has(input:checked) span::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:nth-child(8):has(input:checked) p::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%230F9D8A' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z'/%3E%3Cpolyline points='17 21 17 13 7 13 7 21'/%3E%3Cpolyline points='7 3 7 8 15 8'/%3E%3C/svg%3E");
}

/* Enterprise Data Tables */
div[data-testid="stDataFrame"] {
    border: 1px solid var(--ms-border) !important;
    border-radius: var(--ms-radius) !important;
    overflow: hidden !important;
    background-color: var(--ms-white) !important;
    box-shadow: var(--ms-shadow-sm) !important;
}

div[data-testid="stDataFrame"] [data-testid="glide-cell"] {
    font-family: 'Inter', sans-serif !important;
    font-size: 0.85rem !important;
}

table {
    border-collapse: separate !important;
    border-spacing: 0 !important;
    width: 100% !important;
    border: 1px solid var(--ms-border) !important;
    border-radius: var(--ms-radius) !important;
    overflow: hidden !important;
    background-color: var(--ms-white) !important;
}

th {
    background-color: #F8FAFC !important;
    color: var(--ms-slate) !important;
    font-size: 0.74rem !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
    padding: 10px 14px !important;
    border-bottom: 1px solid var(--ms-border) !important;
}

td {
    padding: 10px 14px !important;
    font-size: 0.85rem !important;
    border-bottom: 1px solid #F2F4F7 !important;
    color: var(--ms-midnight) !important;
}

tr:last-child td {
    border-bottom: none !important;
}

/* --------------------------------------------------------------------------
   BUTTONS: Teal Primary & Clean Secondary
   -------------------------------------------------------------------------- */
button[kind="primary"], .stButton > button[kind="primary"], .stButton > button[type="primary"] {
    background-color: var(--ms-teal) !important;
    color: #FFFFFF !important;
    border: none !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    font-size: 0.875rem !important;
    padding: 8px 16px !important;
    box-shadow: var(--ms-shadow-sm) !important;
    transition: all 0.15s ease !important;
}

button[kind="primary"]:hover, .stButton > button[kind="primary"]:hover {
    background-color: var(--ms-teal-hover) !important;
    box-shadow: var(--ms-shadow-md) !important;
}

button[kind="secondary"], .stButton > button {
    background-color: var(--ms-white) !important;
    color: #344054 !important;
    border: 1px solid #D0D5DD !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    font-size: 0.875rem !important;
    box-shadow: var(--ms-shadow-sm) !important;
    transition: all 0.15s ease !important;
}

button[kind="secondary"]:hover, .stButton > button:hover {
    background-color: #F9FAFB !important;
    border-color: var(--ms-teal) !important;
    color: var(--ms-teal) !important;
}

/* Sidebar Specific Buttons */
section[data-testid="stSidebar"] .stButton > button {
    background-color: var(--ms-slate-dark) !important;
    color: #F2F4F7 !important;
    border: 1px solid #344054 !important;
}
section[data-testid="stSidebar"] .stButton > button:hover {
    background-color: #243447 !important;
    border-color: var(--ms-teal) !important;
    color: #FFFFFF !important;
}

/* --------------------------------------------------------------------------
   CARDS, PANELS, AND CONTAINERS
   -------------------------------------------------------------------------- */
.ms-card {
    background-color: var(--ms-white);
    border: 1px solid var(--ms-border);
    border-radius: var(--ms-radius);
    padding: 20px 24px;
    margin-bottom: 16px;
    box-shadow: var(--ms-shadow-sm);
    transition: box-shadow 0.15s ease, border-color 0.15s ease;
}

.ms-card:hover {
    border-color: #D0D5DD;
    box-shadow: var(--ms-shadow-md);
}

/* Metric Cards */
.metric-card, .ms-metric-card {
    background: var(--ms-white);
    border: 1px solid var(--ms-border);
    border-radius: var(--ms-radius);
    padding: 18px 20px;
    box-shadow: var(--ms-shadow-sm);
    margin-bottom: 12px;
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.metric-lbl, .ms-metric-lbl {
    font-size: 0.72rem;
    font-weight: 700;
    color: var(--ms-slate);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 6px;
}

.metric-val, .ms-metric-val {
    font-size: 2.1rem;
    font-weight: 800;
    line-height: 1.1;
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    letter-spacing: -0.02em;
}

.metric-sub, .ms-metric-sub {
    font-size: 0.76rem;
    color: var(--ms-slate);
    margin-top: 6px;
    font-weight: 500;
}

/* --------------------------------------------------------------------------
   SEMANTIC STATUS BADGES (High Contrast & Consistent)
   -------------------------------------------------------------------------- */
.ms-badge, .badge-allowed, .badge-blocked, .badge-warning {
    display: inline-flex !important;
    align-items: center !important;
    gap: 5px !important;
    padding: 3px 9px !important;
    border-radius: 5px !important;
    font-weight: 700 !important;
    font-size: 0.75rem !important;
    letter-spacing: 0.04em !important;
    text-transform: uppercase !important;
    line-height: 1.2 !important;
}

.badge-allowed, .ms-badge-allowed {
    background-color: var(--ms-green-bg) !important;
    color: var(--ms-green) !important;
    border: 1px solid var(--ms-green-border) !important;
}

.badge-blocked, .ms-badge-blocked {
    background-color: var(--ms-red-bg) !important;
    color: var(--ms-red) !important;
    border: 1px solid var(--ms-red-border) !important;
}

.badge-warning, .ms-badge-warning {
    background-color: var(--ms-amber-bg) !important;
    color: var(--ms-amber) !important;
    border: 1px solid var(--ms-amber-border) !important;
}

.ms-badge-info {
    background-color: var(--ms-blue-bg) !important;
    color: var(--ms-blue) !important;
    border: 1px solid var(--ms-blue-border) !important;
}

.ms-badge-neutral {
    background-color: #F2F4F7 !important;
    color: #344054 !important;
    border: 1px solid #D0D5DD !important;
}

/* Risk Badges */
.risk-high {
    background-color: var(--ms-red-bg) !important;
    color: var(--ms-red) !important;
    border: 1px solid var(--ms-red-border) !important;
    padding: 2px 7px !important;
    border-radius: 4px !important;
    font-size: 0.72rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.04em !important;
}

.risk-med {
    background-color: var(--ms-amber-bg) !important;
    color: var(--ms-amber) !important;
    border: 1px solid var(--ms-amber-border) !important;
    padding: 2px 7px !important;
    border-radius: 4px !important;
    font-size: 0.72rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.04em !important;
}

.risk-low {
    background-color: var(--ms-green-bg) !important;
    color: var(--ms-green) !important;
    border: 1px solid var(--ms-green-border) !important;
    padding: 2px 7px !important;
    border-radius: 4px !important;
    font-size: 0.72rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.04em !important;
}

/* --------------------------------------------------------------------------
   EXPANDERS & DATA PANELS
   -------------------------------------------------------------------------- */
div[data-testid="stExpander"] {
    background-color: var(--ms-white) !important;
    border: 1px solid var(--ms-border) !important;
    border-radius: var(--ms-radius) !important;
    box-shadow: var(--ms-shadow-sm) !important;
    margin-bottom: 8px !important;
    overflow: hidden !important;
    transition: all 0.15s ease !important;
}

div[data-testid="stExpander"]:hover {
    border-color: #CBD5E1 !important;
    box-shadow: var(--ms-shadow-md) !important;
}

div[data-testid="stExpander"] summary {
    padding: 12px 16px !important;
    background-color: var(--ms-white) !important;
    font-weight: 600 !important;
    font-size: 0.9rem !important;
    color: var(--ms-midnight) !important;
}

div[data-testid="stExpander"] summary:hover {
    background-color: #F8FAFC !important;
}

div[data-testid="stExpanderDetails"] {
    border-top: 1px solid var(--ms-border) !important;
    padding: 18px 20px !important;
    background-color: var(--ms-white) !important;
}

/* Nested expanders inside details */
div[data-testid="stExpanderDetails"] div[data-testid="stExpander"] {
    background-color: #F8FAFC !important;
    border: 1px solid var(--ms-border) !important;
    border-radius: 6px !important;
    box-shadow: none !important;
}

/* --------------------------------------------------------------------------
   INPUTS, SELECTS, AND TABS
   -------------------------------------------------------------------------- */
.stTextInput > div > div > input,
.stSelectbox > div > div > div {
    background-color: var(--ms-white) !important;
    border: 1px solid #D0D5DD !important;
    border-radius: 6px !important;
    color: var(--ms-midnight) !important;
    font-size: 0.875rem !important;
}

.stTextInput > div > div > input:focus,
.stSelectbox > div > div > div:focus {
    border-color: var(--ms-teal) !important;
    box-shadow: 0 0 0 3px rgba(15, 157, 138, 0.12) !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px !important;
    border-bottom: 1px solid var(--ms-border) !important;
    padding-bottom: 2px !important;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 6px 6px 0 0 !important;
    padding: 8px 16px !important;
    font-weight: 600 !important;
    font-size: 0.875rem !important;
    color: var(--ms-slate) !important;
    border-bottom: 2px solid transparent !important;
}

.stTabs [aria-selected="true"] {
    color: var(--ms-teal) !important;
    border-bottom: 2px solid var(--ms-teal) !important;
    background-color: transparent !important;
}

/* Monospace code snippet styling */
code {
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
    font-size: 0.84em !important;
    background-color: #F2F4F7 !important;
    color: #344054 !important;
    padding: 2px 5px !important;
    border-radius: 4px !important;
    border: 1px solid #EAECF0 !important;
}

pre {
    border-radius: 6px !important;
    border: 1px solid var(--ms-border) !important;
}

/* Operational Status Banner */
.status-banner {
    background: var(--ms-white);
    border: 1px solid var(--ms-border);
    border-left: 4px solid var(--ms-teal);
    padding: 12px 18px;
    border-radius: 8px;
    margin-bottom: 18px;
    box-shadow: var(--ms-shadow-sm);
}

/* Module Entry Cards */
.ms-module-card {
    background: var(--ms-white);
    border: 1px solid var(--ms-border);
    border-radius: var(--ms-radius);
    padding: 16px 18px;
    box-shadow: var(--ms-shadow-sm);
    transition: all 0.15s ease-in-out;
    height: 100%;
}
.ms-module-card:hover {
    border-color: var(--ms-teal);
    box-shadow: var(--ms-shadow-md);
    transform: translateY(-1px);
}

/* Comparative Analysis Cards (Guard-Off vs Guard-On) */
.comp-card-vulnerable {
    background: #FFFFFF;
    border: 1px solid #FECDCA;
    border-top: 4px solid var(--ms-red);
    border-radius: 8px;
    padding: 18px 20px;
    box-shadow: var(--ms-shadow-sm);
    height: 100%;
}

.comp-card-protected {
    background: #FFFFFF;
    border: 1px solid #A6F4C5;
    border-top: 4px solid var(--ms-teal);
    border-radius: 8px;
    padding: 18px 20px;
    box-shadow: var(--ms-shadow-sm);
    height: 100%;
}

/* Security Test Runner Card */
.ms-test-card {
    background: #FFFFFF;
    border: 1px solid var(--ms-border);
    border-radius: 8px;
    padding: 18px 20px;
    margin-bottom: 16px;
    box-shadow: var(--ms-shadow-sm);
}

/* Stepper Workflow Flow */
.stepper-step {
    background: #FFFFFF;
    border: 1px solid var(--ms-border);
    border-radius: 8px;
    padding: 12px 14px;
    text-align: center;
    flex: 1;
    min-width: 130px;
    transition: all 0.15s ease;
}
.stepper-step:hover {
    border-color: var(--ms-teal);
    box-shadow: var(--ms-shadow-sm);
}
.stepper-step-active {
    background: var(--ms-mint-light);
    border: 1px solid var(--ms-teal);
}
.stepper-arrow {
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--ms-teal);
    font-size: 1.1rem;
    padding: 0 4px;
}
</style>
"""


def inject_enterprise_theme() -> None:
    """Inject the unified MediShield enterprise design system stylesheet into the Streamlit app."""
    if hasattr(st, "html"):
        st.html(ENTERPRISE_CSS)
    st.markdown(ENTERPRISE_CSS, unsafe_allow_html=True)


# ==============================================================================
# SECTION 3: Header, Banner, and Branding Components
# ==============================================================================

def render_brand_sidebar_header() -> None:
    """Render the official MediShield enterprise wordmark and logo in the sidebar."""
    header_html = f"""
    <div style="padding: 12px 0 18px 0; border-bottom: 1px solid #1D2939; margin-bottom: 14px;">
        <div style="display: flex; align-items: center; gap: 10px;">
            <div>{MEDISHIELD_SHIELD_SVG}</div>
            <div>
                <div style="font-size: 1.45rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.02em; line-height: 1.1;">
                    MediShield
                </div>
                <div style="font-size: 0.68rem; color: #0F9D8A; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 2px;">
                    Runtime Security Gateway
                </div>
            </div>
        </div>
        <div style="font-size: 0.68rem; color: #667085; margin-top: 8px; line-height: 1.3;">
            Enterprise B2B Healthcare Operations & MCP Protection
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)


def render_page_header(
    title: str,
    subtitle: str,
    badge_label: Optional[str] = None,
    badge_type: str = "allowed",
    refresh_key: Optional[str] = None,
    last_refresh_time: Any = None,
    to_ist_fn: Any = None,
) -> None:
    """Render a clean, authoritative enterprise page header with title, subtitle, and metadata."""
    badge_html = ""
    if badge_label:
        badge_class = f"ms-badge-{badge_type}"
        badge_html = f'<span class="ms-badge {badge_class}" style="margin-left: 10px; font-size: 0.72rem;">{html.escape(badge_label)}</span>'

    c_left, c_right = st.columns([5, 1.2])
    with c_left:
        st.markdown(
            f"""
            <div style="margin-bottom: 14px;">
                <div style="font-size: 0.72rem; font-weight: 700; color: #0F9D8A; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                    <span>MEDISHIELD</span>
                    <span style="color: #D0D5DD;">•</span>
                    <span style="color: #667085;">RUNTIME SECURITY GATEWAY</span>
                </div>
                <div style="display: flex; align-items: center; flex-wrap: wrap;">
                    <h1 style="margin: 0; font-size: 1.85rem; font-weight: 800; color: #101828;">{html.escape(title)}</h1>
                    {badge_html}
                </div>
                <p style="color: #667085; font-size: 0.96rem; margin: 4px 0 0 0; line-height: 1.45;">
                    {html.escape(subtitle)}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c_right:
        if refresh_key:
            st.write("")
            if st.button("🔄 Refresh Data", key=refresh_key, use_container_width=True):
                st.session_state["last_refresh_time"] = datetime.now(timezone.utc)
                st.rerun()
            if last_refresh_time and to_ist_fn:
                st.markdown(
                    f"""
                    <div style="font-size: 0.7rem; color: #667085; text-align: right; margin-top: -4px;">
                        Refreshed: <span style="font-weight: 600; color: #101828;">{to_ist_fn(last_refresh_time)}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )


def render_status_pill(status: str, label: Optional[str] = None) -> str:
    """Generate high-contrast semantic HTML badge string."""
    s = str(status).lower()
    lbl = label or status.upper()
    if s in ("allowed", "active", "trusted", "healthy", "verified", "true"):
        return f'<span class="ms-badge ms-badge-allowed">{get_icon_svg("check", "#079455", 14)} {html.escape(lbl)}</span>'
    elif s in ("blocked", "failed", "unauthorized", "drift", "tampered", "revoked", "false", "error"):
        return f'<span class="ms-badge ms-badge-blocked">{get_icon_svg("blocked", "#D92D20", 14)} {html.escape(lbl)}</span>'
    elif s in ("warning", "pending", "advisory", "review", "degraded"):
        return f'<span class="ms-badge ms-badge-warning">{get_icon_svg("warning", "#B54708", 14)} {html.escape(lbl)}</span>'
    elif s in ("info", "simulated", "audit"):
        return f'<span class="ms-badge ms-badge-info">{get_icon_svg("info", "#175CD3", 14)} {html.escape(lbl)}</span>'
    else:
        return f'<span class="ms-badge ms-badge-neutral">{html.escape(lbl)}</span>'


def render_metric_card(
    label: str,
    value: Any,
    subtext: Optional[str] = None,
    status_color: Optional[str] = None,
    help_text: Optional[str] = None,
) -> str:
    """Generate HTML for a polished enterprise metric card."""
    color_style = f"color: {status_color};" if status_color else "color: #101828;"
    sub_html = f'<div class="metric-sub">{html.escape(subtext)}</div>' if subtext else ""
    tooltip_attr = f'title="{html.escape(help_text)}"' if help_text else ""
    return f"""
    <div class="metric-card" {tooltip_attr}>
        <div class="metric-lbl">{html.escape(label)}</div>
        <div class="metric-val" style="{color_style}">{html.escape(str(value))}</div>
        {sub_html}
    </div>
    """


def render_module_summary_card(
    title: str,
    description: str,
    icon_name: str,
    status_text: str,
    status_type: str = "neutral",
) -> str:
    """Generate HTML for a compact security module card in the overview page."""
    icon_svg = get_icon_svg(icon_name, "#0F9D8A", 20)
    badge_html = render_status_pill(status_type, status_text)
    return f"""
    <div class="ms-module-card">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <div style="background: #E8F7F3; border-radius: 6px; padding: 6px; display: inline-flex;">
                    {icon_svg}
                </div>
                <div style="font-weight: 700; color: #101828; font-size: 0.95rem;">
                    {html.escape(title)}
                </div>
            </div>
            <div>{badge_html}</div>
        </div>
        <div style="font-size: 0.8rem; color: #667085; line-height: 1.45; margin-top: 6px;">
            {html.escape(description)}
        </div>
    </div>
    """


def render_empty_state_box(title: str, description: str, icon_name: str = "info") -> None:
    """Render a clean, bounded empty state container."""
    icon_svg = get_icon_svg(icon_name, "#667085", 28)
    st.markdown(
        f"""
        <div style="background: #FFFFFF; border: 1px dashed #D0D5DD; border-radius: 8px; padding: 32px 20px; text-align: center; margin: 16px 0;">
            <div style="display: inline-flex; background: #F2F4F7; border-radius: 50%; padding: 12px; margin-bottom: 10px;">
                {icon_svg}
            </div>
            <div style="font-weight: 700; color: #101828; font-size: 1rem; margin-bottom: 4px;">
                {html.escape(title)}
            </div>
            <div style="font-size: 0.84rem; color: #667085; max-width: 440px; margin: 0 auto;">
                {html.escape(description)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_comparative_banner(
    approved_dose: str,
    tampered_dose: str,
    vulnerable_state_changed: bool,
    protected_state_changed: bool,
    protected_rule: str,
) -> None:
    """Render authoritative side-by-side comparative analysis between Guard-Off and Guard-On."""
    vuln_badge = render_status_pill("blocked", "BYPASSED (NO GATEWAY)")
    vuln_state_badge = render_status_pill("blocked", "CORRUPTED (STATE CHANGED)" if vulnerable_state_changed else "UNALTERED")
    prot_badge = render_status_pill("allowed", "BLOCKED (FAIL-CLOSED)")
    prot_state_badge = render_status_pill("allowed", "PROTECTED (STATE UNTOUCHED)" if not protected_state_changed else "CORRUPTED")

    c_left, c_right = st.columns(2)
    with c_left:
        st.markdown(
            f"""
            <div class="comp-card-vulnerable">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-weight: 800; font-size: 1rem; color: #D92D20;">❌ Guard-Off Baseline</span>
                        <span style="font-size: 0.72rem; color: #667085;">(Vulnerable MCP Engine)</span>
                    </div>
                    <div>{vuln_badge}</div>
                </div>
                <div style="font-size: 0.84rem; color: #475467; margin-bottom: 12px; line-height: 1.45;">
                    Direct execution without gateway mediation. Rogue agents or hijacked prompts can execute unauthorized mutations directly against clinical records.
                </div>
                <div style="background: #FEF3F2; border: 1px solid #FECDCA; border-radius: 6px; padding: 10px 12px; margin-bottom: 12px;">
                    <div style="font-size: 0.72rem; color: #667085; font-weight: 700; text-transform: uppercase;">Prescription Tampering Delta:</div>
                    <div style="font-size: 0.88rem; color: #101828; margin-top: 4px;">
                        Prescribed: <code>{html.escape(approved_dose)}</code> ➔ 
                        Executed: <b style="color: #D92D20; font-family: 'JetBrains Mono', monospace;">{html.escape(tampered_dose)}</b>
                    </div>
                </div>
                <div style="display: flex; align-items: center; justify-content: space-between; font-size: 0.8rem; color: #475467; border-top: 1px solid #F2F4F7; padding-top: 10px;">
                    <span>Clinical Database State:</span>
                    <div>{vuln_state_badge}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c_right:
        st.markdown(
            f"""
            <div class="comp-card-protected">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-weight: 800; font-size: 1rem; color: #0F9D8A;">🛡️ Guard-On MediShield</span>
                        <span style="font-size: 0.72rem; color: #667085;">(Runtime Security Gateway)</span>
                    </div>
                    <div>{prot_badge}</div>
                </div>
                <div style="font-size: 0.84rem; color: #475467; margin-bottom: 12px; line-height: 1.45;">
                    Every action is canonicalized, cryptographically compared against the clinician's HMAC intent lock, and checked fail-closed before any database write.
                </div>
                <div style="background: #E8F7F3; border: 1px solid #A6F4C5; border-radius: 6px; padding: 10px 12px; margin-bottom: 12px;">
                    <div style="font-size: 0.72rem; color: #667085; font-weight: 700; text-transform: uppercase;">Cryptographic Invariant Enforcement:</div>
                    <div style="font-size: 0.88rem; color: #101828; margin-top: 4px;">
                        Security Rule: <code>{html.escape(protected_rule)}</code> ➔ 
                        Protected Dose: <b style="color: #079455; font-family: 'JetBrains Mono', monospace;">{html.escape(approved_dose)}</b>
                    </div>
                </div>
                <div style="display: flex; align-items: center; justify-content: space-between; font-size: 0.8rem; color: #475467; border-top: 1px solid #F2F4F7; padding-top: 10px;">
                    <span>Clinical Database State:</span>
                    <div>{prot_state_badge}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_test_scenario_card(
    test_num: int,
    title: str,
    description: str,
    expected_decision: str,
    expected_rule: str,
    actual_decision: str,
    actual_rule: str,
    actual_reason: str,
    request_id: str,
    backend_details: List[Tuple[str, str]],
    is_pass: bool,
    pass_message: str,
) -> None:
    """Render a structured, beautiful test scenario card with telemetry and state verification."""
    exp_pill = render_status_pill(expected_decision, expected_decision.upper())
    act_pill = render_status_pill(actual_decision, actual_decision.upper())
    res_pill = render_status_pill("allowed" if is_pass else "blocked", "PASS" if is_pass else "FAIL")

    st.markdown(
        f"""
        <div class="ms-test-card">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; border-bottom: 1px solid #E4E7EC; padding-bottom: 10px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="background: #1D2939; color: #FFFFFF; font-size: 0.72rem; font-weight: 800; padding: 3px 8px; border-radius: 4px;">
                        TEST {test_num}
                    </span>
                    <span style="font-size: 1.05rem; font-weight: 700; color: #101828;">
                        {html.escape(title)}
                    </span>
                </div>
                <div>{res_pill}</div>
            </div>
            <div style="font-size: 0.84rem; color: #667085; margin-bottom: 14px;">
                {html.escape(description)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            f"""
            <div style="background: #F8FAFC; border: 1px solid #E4E7EC; border-radius: 6px; padding: 12px; margin-bottom: 10px;">
                <div style="font-size: 0.72rem; color: #667085; font-weight: 700; text-transform: uppercase; margin-bottom: 6px;">
                    Gateway Enforcement Telemetry
                </div>
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                    <span style="font-size: 0.82rem; color: #344054;">Expected Result:</span>
                    <div>{exp_pill} <span style="font-size: 0.75rem; color: #667085;">({html.escape(expected_rule)})</span></div>
                </div>
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                    <span style="font-size: 0.82rem; color: #344054;">Actual Verdict:</span>
                    <div>{act_pill}</div>
                </div>
                <div style="font-size: 0.82rem; color: #344054; margin-top: 4px;">
                    Security Rule: <code>{html.escape(actual_rule)}</code>
                </div>
                <div style="font-size: 0.8rem; color: #667085; margin-top: 6px; line-height: 1.4;">
                    <b>Reason:</b> {html.escape(actual_reason)}
                </div>
                <div style="font-size: 0.72rem; color: #98A2B3; margin-top: 8px;">
                    Request ID: <code>{html.escape(request_id)}</code>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        details_html = "".join(
            f'<div style="display: flex; justify-content: space-between; font-size: 0.82rem; margin-bottom: 4px;">'
            f'<span style="color: #667085;">{html.escape(k)}:</span>'
            f'<b style="color: #101828; font-family: monospace;">{html.escape(v)}</b>'
            f'</div>'
            for k, v in backend_details
        )
        st.markdown(
            f"""
            <div style="background: #F8FAFC; border: 1px solid #E4E7EC; border-radius: 6px; padding: 12px; margin-bottom: 10px;">
                <div style="font-size: 0.72rem; color: #667085; font-weight: 700; text-transform: uppercase; margin-bottom: 8px;">
                    Protected Backend Verification
                </div>
                {details_html}
            </div>
            """,
            unsafe_allow_html=True,
        )

    if is_pass:
        st.success(pass_message)
    else:
        st.error(pass_message)


def render_stepper_flow(steps: List[Dict[str, Any]]) -> None:
    """Render a modern horizontal stepper workflow bar."""
    step_items = []
    for i, s in enumerate(steps):
        is_active = s.get("active", False)
        step_class = "stepper-step stepper-step-active" if is_active else "stepper-step"
        num = s.get("num", f"0{i+1}")
        title = s.get("title", "")
        sub = s.get("sub", "")
        badge_pill = render_status_pill(s.get("badge_type", "neutral"), s.get("badge", "")) if s.get("badge") else ""

        step_html = f"""
        <div class="{step_class}">
            <div style="font-size: 0.68rem; font-weight: 800; color: #0F9D8A; text-transform: uppercase; letter-spacing: 0.06em;">
                STEP {num}
            </div>
            <div style="font-size: 0.88rem; font-weight: 700; color: #101828; margin: 2px 0;">
                {html.escape(title)}
            </div>
            <div style="font-size: 0.72rem; color: #667085; line-height: 1.3;">
                {html.escape(sub)}
            </div>
            {f'<div style="margin-top: 6px;">{badge_pill}</div>' if badge_pill else ''}
        </div>
        """
        step_items.append(step_html)

    stepper_container = f"""
    <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; margin: 14px 0 18px 0;">
        {'<div class="stepper-arrow">➔</div>'.join(step_items)}
    </div>
    """
    st.markdown(stepper_container, unsafe_allow_html=True)


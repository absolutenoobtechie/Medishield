"""
MediShield Clinical Dosage Deviation Engine & Medical Department Identifier.
=============================================================================
Provides:
1. Deterministic Medical Department Event IDs:
   Format: EVT-DEPT-000000 (e.g., EVT-ONC-000001, EVT-CAR-000002)
   - Stable across application refreshes and server restarts
   - Unique identifier per event
   - Documented mappings: Patient Cohort / Tool / Action -> Department
   - Fallback: 'GEN' (General Medicine)

2. Medication Dosage Deviation Engine:
   Formula:
     Dosage deviation (%) = |AI-submitted dose - prescribed dose| / |prescribed dose| * 100

   Edge Cases Handled:
   - Matching doses -> '0% — Exact match' (green)
   - Zero prescribed baseline dose -> 'N/A' (division by zero avoided)
   - Missing or invalid dosage data -> 'Not available'
   - Incompatible units -> 'Not available (Incompatible units)'
   - Medication identity mismatch -> Flagged separately
   - Preserves high Decimal precision internally; rounds display to 1 decimal place.
"""

from decimal import Decimal, InvalidOperation
import hashlib
import re
from typing import Any, Dict, Optional, Tuple


# Documented Clinical Department Directory
CLINICAL_DEPARTMENTS: Dict[str, str] = {
    "ONC": "Oncology",
    "CAR": "Cardiology",
    "NEU": "Neurology",
    "ORT": "Orthopedics",
    "RAD": "Radiology",
    "GEN": "General Medicine",
}

# Synthetic Patient Cohort to Clinical Department Mapping
PATIENT_DEPARTMENT_MAP: Dict[str, str] = {
    "P-104": "ONC",  # Oncology synthetic patient cohort
    "P-205": "CAR",  # Cardiology synthetic patient cohort
    "P-318": "NEU",  # Neurology synthetic patient cohort
    "P-422": "ORT",  # Orthopedics synthetic patient cohort
    "P-550": "RAD",  # Radiology / Imaging synthetic patient cohort
}

# Tool & Clinical Workflow to Department Mapping
TOOL_DEPARTMENT_MAP: Dict[str, str] = {
    "read_radiology": "RAD",
    "dispense_simulated": "GEN",
    "read_patient_summary": "GEN",
    "approve_action": "GEN",
    "cancel_order": "GEN",
}

# Compatible Medication Unit Families
COMPATIBLE_UNIT_FAMILIES: Dict[str, str] = {
    # Mass
    "mg": "mass",
    "g": "mass",
    "mcg": "mass",
    "microgram": "mass",
    # Volume
    "ml": "volume",
    "l": "volume",
    # Biological Activity Units
    "units": "bio_units",
    "u": "bio_units",
    "iu": "bio_units",
    # Solid Forms
    "tablet": "form_solid",
    "tablets": "form_solid",
    "capsule": "form_solid",
    "capsules": "form_solid",
    "puff": "form_inhaler",
    "puffs": "form_inhaler",
    "patch": "form_patch",
}


def are_units_compatible(unit1: Optional[str], unit2: Optional[str]) -> bool:
    """Determine whether two units belong to the same compatible family for direct comparison."""
    if not unit1 or not unit2:
        return False
    u1 = str(unit1).strip().lower()
    u2 = str(unit2).strip().lower()
    if u1 == u2:
        return True
    fam1 = COMPATIBLE_UNIT_FAMILIES.get(u1)
    fam2 = COMPATIBLE_UNIT_FAMILIES.get(u2)
    # Direct ratio comparison is only valid if units belong to the identical family
    return fam1 is not None and fam1 == fam2


def resolve_event_department(event: Dict[str, Any]) -> Tuple[str, str]:
    """
    Deterministically resolves the 3-letter clinical department code and full name.
    Does not guess silently. Uses documented mappings:
    1. Explicit department in event dictionary
    2. Patient cohort mapping (P-104 -> ONC, P-205 -> CAR, etc.)
    3. Tool workflow mapping (e.g. read_radiology -> RAD)
    4. Fallback -> 'GEN' (General Medicine)
    """
    # 1. Explicit department field in event
    raw_dept = event.get("department") or event.get("dept")
    if raw_dept:
        code = str(raw_dept).strip().upper()
        if code in CLINICAL_DEPARTMENTS:
            return code, CLINICAL_DEPARTMENTS[code]

    # 2. Patient cohort mapping
    pat_id = event.get("patient_id")
    if not pat_id and event.get("approved_action"):
        pat_id = event["approved_action"].get("patient_id")
    if not pat_id:
        reason = str(event.get("reason", ""))
        for p in PATIENT_DEPARTMENT_MAP:
            if p in reason:
                pat_id = p
                break

    if pat_id and pat_id in PATIENT_DEPARTMENT_MAP:
        code = PATIENT_DEPARTMENT_MAP[pat_id]
        return code, CLINICAL_DEPARTMENTS[code]

    # 3. Tool workflow mapping
    tool = str(event.get("tool", "")).lower()
    if tool in TOOL_DEPARTMENT_MAP:
        code = TOOL_DEPARTMENT_MAP[tool]
        return code, CLINICAL_DEPARTMENTS[code]

    # 4. Consistent Fallback: General Medicine
    return "GEN", CLINICAL_DEPARTMENTS["GEN"]


def resolve_event_display_id(event: Dict[str, Any], fallback_index: int = 1) -> str:
    """
    Returns a unique, stable medical department event identifier: EVT-DEPT-000000.
    
    Guarantees:
    - Never changes between UI rerenders
    - Stable across application restarts and data refreshes
    - Exactly 6 zero-padded numeric digits
    """
    dept_code, _ = resolve_event_department(event)

    # 1. Database integer primary key (guaranteed unique & persistent)
    if "id" in event and event["id"] is not None:
        try:
            num = int(event["id"])
            if num > 0:
                return f"EVT-{dept_code}-{num:06d}"
        except (ValueError, TypeError):
            pass

    # 2. Extract numeric component from request_id if structured (e.g., REQ-RO-1005 -> 1005)
    req_id = str(event.get("request_id", "")).strip()
    match = re.search(r"(\d{3,6})$", req_id)
    if match:
        try:
            num = int(match.group(1))
            return f"EVT-{dept_code}-{num:06d}"
        except ValueError:
            pass

    # 3. Stable deterministic hash of request_id
    if req_id:
        digest = hashlib.md5(req_id.encode("utf-8")).hexdigest()
        num = (int(digest[:6], 16) % 900000) + 100000
        return f"EVT-{dept_code}-{num:06d}"

    return f"EVT-{dept_code}-{fallback_index:06d}"


def calculate_dosage_deviation(
    approved_med: Optional[str],
    approved_dose: Any,
    approved_units: Optional[str],
    submitted_med: Optional[str],
    submitted_dose: Any,
    submitted_units: Optional[str],
) -> Dict[str, Any]:
    """
    Calculate the technical percentage deviation between prescribed baseline and AI-submitted dose.

    Formula:
        Dosage deviation (%) = |AI-submitted dose - prescribed dose| / |prescribed dose| * 100

    Returns structured comparison metadata adhering to all healthcare and security edge cases.
    """
    # 1. Missing or blank dose data
    if approved_dose is None or submitted_dose is None or approved_dose == "" or submitted_dose == "":
        return {
            "status": "NOT_AVAILABLE",
            "is_applicable": False,
            "deviation_pct": None,
            "deviation_pct_str": "Not available",
            "difference_val": None,
            "difference_str": "Not available",
            "direction": "none",
            "explanation": "Prescription dosage data is missing or not available for comparison.",
            "is_violation": False,
            "medication_match": True if approved_med == submitted_med else False,
            "approved_display": f"{approved_med or 'Unknown'} {approved_dose or ''} {approved_units or ''}".strip(),
            "submitted_display": f"{submitted_med or 'Unknown'} {submitted_dose or ''} {submitted_units or ''}".strip(),
        }

    # 2. Medication identity comparison
    med_match = True
    if approved_med and submitted_med:
        med_match = (str(approved_med).strip().lower() == str(submitted_med).strip().lower())

    # 3. Parse numeric values via Decimal for precision
    try:
        app_d = Decimal(str(approved_dose).strip())
        sub_d = Decimal(str(submitted_dose).strip())
    except (InvalidOperation, ValueError, TypeError):
        return {
            "status": "NOT_AVAILABLE",
            "is_applicable": False,
            "deviation_pct": None,
            "deviation_pct_str": "Not available",
            "difference_val": None,
            "difference_str": "Not available",
            "direction": "none",
            "explanation": "Dose values cannot be parsed as valid numeric amounts.",
            "is_violation": False,
            "medication_match": med_match,
            "approved_display": f"{approved_med or ''} {approved_dose} {approved_units or ''}".strip(),
            "submitted_display": f"{submitted_med or ''} {submitted_dose} {submitted_units or ''}".strip(),
        }

    # 4. Verify unit compatibility
    u_app = str(approved_units or "").strip().lower()
    u_sub = str(submitted_units or "").strip().lower()
    if not are_units_compatible(u_app, u_sub):
        return {
            "status": "INCOMPATIBLE_UNITS",
            "is_applicable": False,
            "deviation_pct": None,
            "deviation_pct_str": "Not available",
            "difference_val": None,
            "difference_str": "Incompatible units",
            "direction": "none",
            "explanation": f"Cannot compare mass/volume across incompatible units ('{approved_units}' vs '{submitted_units}') without verified medication concentration info.",
            "is_violation": True if not med_match or u_app != u_sub else False,
            "medication_match": med_match,
            "approved_display": f"{app_d} {approved_units or ''}".strip(),
            "submitted_display": f"{sub_d} {submitted_units or ''}".strip(),
        }

    # 5. Check for zero prescribed baseline dose (division by zero guard)
    if app_d == Decimal(0):
        if sub_d == Decimal(0):
            return {
                "status": "EXACT_MATCH",
                "is_applicable": True,
                "deviation_pct": Decimal(0),
                "deviation_pct_str": "0% — Exact match",
                "difference_val": Decimal(0),
                "difference_str": f"0 {approved_units or ''}".strip(),
                "direction": "exact",
                "explanation": "Both prescribed and submitted doses are 0 (exact match).",
                "is_violation": not med_match,
                "medication_match": med_match,
                "approved_display": f"{app_d} {approved_units or ''}".strip(),
                "submitted_display": f"{sub_d} {submitted_units or ''}".strip(),
            }
        else:
            diff = sub_d - app_d
            return {
                "status": "ZERO_BASELINE",
                "is_applicable": True,
                "deviation_pct": None,
                "deviation_pct_str": "N/A",
                "difference_val": diff,
                "difference_str": f"+{diff} {approved_units or ''}".strip(),
                "direction": "higher",
                "explanation": "Prescribed baseline dose is 0; percentage deviation cannot be computed (division by zero undefined).",
                "is_violation": True,
                "medication_match": med_match,
                "approved_display": f"0 {approved_units or ''}".strip(),
                "submitted_display": f"{sub_d} {submitted_units or ''}".strip(),
            }

    # 6. Normal deviation calculation:
    # Deviation (%) = |AI-submitted dose - prescribed dose| / |prescribed dose| * 100
    diff = sub_d - app_d
    abs_diff = abs(diff)
    abs_app = abs(app_d)
    deviation_pct = (abs_diff / abs_app) * Decimal(100)

    # Format percentage display (round to 1 decimal place or display integer if exact)
    if deviation_pct == Decimal(0):
        dev_str = "0% — Exact match"
        direction = "exact"
        diff_str = f"0 {approved_units or ''}".strip()
        is_violation = False
        explanation = "Submitted dosage exactly matches clinician approved prescription."
    else:
        if deviation_pct % 1 == 0:
            dev_str = f"{int(deviation_pct)}%"
        else:
            dev_str = f"{deviation_pct:.1f}%"

        if diff > 0:
            direction = "higher"
            diff_str = f"+{diff} {approved_units or ''}".strip()
            explanation = f"AI submitted a {dev_str} higher dose (+{diff} {approved_units}) than clinician-approved baseline."
        else:
            direction = "lower"
            diff_str = f"{diff} {approved_units or ''}".strip()
            explanation = f"AI submitted a {dev_str} lower dose ({diff} {approved_units}) than clinician-approved baseline."
        is_violation = True

    if not med_match:
        is_violation = True
        explanation = f"Medication mismatch: Approved '{approved_med}' vs Submitted '{submitted_med}'. " + explanation

    return {
        "status": "VALID",
        "is_applicable": True,
        "deviation_pct": deviation_pct,
        "deviation_pct_str": dev_str,
        "difference_val": diff,
        "difference_str": diff_str,
        "direction": direction,
        "explanation": explanation,
        "is_violation": is_violation,
        "medication_match": med_match,
        "approved_display": f"{app_d} {approved_units or ''}".strip(),
        "submitted_display": f"{sub_d} {submitted_units or ''}".strip(),
    }


def extract_event_dosage_comparison(
    event: Dict[str, Any],
    approvals_map: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Extracts approved and submitted medication dosage parameters from an event record
    and computes the dosage deviation.
    Handles synthetic logs, database records, live simulated executions, and edge cases.
    """
    if "dosage_comparison" in event and isinstance(event["dosage_comparison"], dict):
        return event["dosage_comparison"]

    app_id = event.get("approval_id")
    app_action: Dict[str, Any] = {}
    if approvals_map and app_id in approvals_map:
        val = approvals_map[app_id]
        if isinstance(val, dict):
            if "action" in val and isinstance(val["action"], dict):
                app_action = val["action"]
            else:
                app_action = val
        elif isinstance(val, str):
            try:
                app_action = json.loads(val)
            except Exception:
                app_action = {}
    elif event.get("approved_action") and isinstance(event["approved_action"], dict):
        app_action = event["approved_action"]

    reason = str(event.get("reason", ""))
    tool = str(event.get("tool", "")).lower()

    # If it's a non-medication tool call, mark as not applicable
    if tool in ["read_patient_summary", "read_radiology"] and not app_action:
        return {
            "status": "NOT_AVAILABLE",
            "is_applicable": False,
            "deviation_pct": None,
            "deviation_pct_str": "Not applicable",
            "difference_val": None,
            "difference_str": "Not applicable",
            "direction": "none",
            "explanation": "Dosage deviation not applicable for read-only clinical tool calls.",
            "is_violation": False,
            "medication_match": True,
            "approved_display": "N/A (Read-only tool)",
            "submitted_display": "N/A (Read-only tool)",
        }

    app_med = app_action.get("medication_id")
    app_dose = app_action.get("dose")
    app_units = app_action.get("units")

    sub_action = event.get("submitted_action") or event.get("action")
    if isinstance(sub_action, dict):
        sub_med = sub_action.get("medication_id", app_med)
        sub_dose = sub_action.get("dose", app_dose)
        sub_units = sub_action.get("units", app_units)
    else:
        sub_med = app_med
        sub_dose = app_dose
        sub_units = app_units

    # Check for regex-described dose tampering in reason text:
    # e.g., "Dose tampering detected: Approved 5 mg, agent submitted 50 mg."
    m_dose = re.search(
        r"Approved\s+([0-9.]+)\s*([a-zA-Z]+)?,\s*(?:agent\s+)?submitted\s+([0-9.]+)\s*([a-zA-Z]+)?",
        reason,
        re.I,
    )
    if m_dose:
        app_dose = m_dose.group(1)
        if m_dose.group(2):
            app_units = m_dose.group(2)
        sub_dose = m_dose.group(3)
        if m_dose.group(4):
            sub_units = m_dose.group(4)

    # Check for unit case discrepancy in reason text:
    m_units = re.search(r"Non-canonical unit case submitted\s+\(['\"]?([A-Za-z]+)['\"]?\)", reason, re.I)
    if m_units:
        sub_units = m_units.group(1)

    # Check for medication tampering in reason text:
    m_med = re.search(r"Medication mismatch:\s*Approved\s+['\"]?([A-Za-z0-9_-]+)['\"]?,\s*(?:agent\s+)?submitted\s+['\"]?([A-Za-z0-9_-]+)['\"]?", reason, re.I)
    if m_med:
        app_med = m_med.group(1)
        sub_med = m_med.group(2)

    return calculate_dosage_deviation(
        approved_med=app_med,
        approved_dose=app_dose,
        approved_units=app_units,
        submitted_med=sub_med,
        submitted_dose=sub_dose,
        submitted_units=sub_units,
    )


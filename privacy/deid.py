"""Local, rule-based PHI detector for synthetic documents.

This is a privacy aid, not a clinical de-identification certification.  The
report deliberately contains categories and counts, never the values matched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .crypto import pseudonym_for


@dataclass(frozen=True)
class _Match:
    category: str
    start: int
    end: int
    value: str


@dataclass(frozen=True)
class DeidentificationResult:
    text: str
    mode: str
    findings: tuple[dict[str, Any], ...]
    counts: dict[str, int]
    review_required: bool
    warnings: tuple[str, ...]

    def report(self) -> dict[str, Any]:
        """Return a non-sensitive JSON-ready processing report."""

        return {
            "mode": self.mode,
            "findings": [dict(item) for item in self.findings],
            "counts": dict(self.counts),
            "review_required": self.review_required,
            "warnings": list(self.warnings),
        }


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "email",
        re.compile(r"(?<![\w.+-])[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w-])"),
    ),
    (
        "phone",
        re.compile(r"(?<!\d)(?:\+?\d[\d().\- ]{7,}\d)(?!\d)"),
    ),
    (
        "mrn",
        re.compile(
            r"(?i)(?:\b(?:mrn|medical record number|patient id|patient identifier)\s*[:#]\s*)([A-Za-z0-9-]+)"
        ),
    ),
    (
        "date",
        re.compile(
            r"(?i)(?:\b(?:dob|date of birth|birth date)\s*[:#]\s*)(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})"
        ),
    ),
    (
        "address",
        re.compile(r"(?im)^\s*address\s*[:#]?\s*([^\r\n]+)"),
    ),
    (
        "person",
        re.compile(
            r"(?i:\bpatient\s+name\s*[:#][ \t]*)([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,3})"
        ),
    ),
    (
        "person",
        re.compile(r"\b(?:John Doe|Jane Smith|Synthetic Patient Alpha|Synthetic Patient Beta)\b"),
    ),
)


def _find_matches(text: str) -> list[_Match]:
    matches: list[_Match] = []
    for category, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            value_group = match.group(1) if match.lastindex else match.group(0)
            start = match.start(1) if match.lastindex else match.start()
            end = match.end(1) if match.lastindex else match.end()
            if value_group and value_group.strip():
                matches.append(_Match(category, start, end, value_group))

    # Prefer the first rule at an overlapping location and make replacement
    # order deterministic across Python versions.
    selected: list[_Match] = []
    for item in sorted(matches, key=lambda value: (value.start, value.end, value.category)):
        if any(item.start < prior.end and prior.start < item.end for prior in selected):
            continue
        selected.append(item)
    return selected


def deidentify_text(text: str, *, mode: str = "redaction", org_id: str = "") -> DeidentificationResult:
    """Detect local PHI-like identifiers and optionally redact/pseudonymize them.

    ``detection`` preserves the input for a privacy reviewer.  ``redaction``
    uses numbered category labels.  ``pseudonymization`` uses stable,
    organization-scoped HMAC-derived labels and never returns a mapping.
    """

    if not isinstance(text, str):
        raise TypeError("document text must be a string")
    if mode not in {"detection", "redaction", "pseudonymization"}:
        raise ValueError("mode must be detection, redaction, or pseudonymization")
    if mode == "pseudonymization" and not org_id:
        raise ValueError("org_id is required for pseudonymization")

    matches = _find_matches(text)
    counts: dict[str, int] = {}
    findings: list[dict[str, Any]] = []
    replacements: list[tuple[int, int, str]] = []
    for item in matches:
        counts[item.category] = counts.get(item.category, 0) + 1
        ordinal = counts[item.category]
        findings.append({"category": item.category, "count": ordinal})
        if mode == "redaction":
            replacement = f"[{item.category.upper()}_{ordinal}]"
        elif mode == "pseudonymization":
            replacement = pseudonym_for(org_id=org_id, category=item.category, value=item.value)
        else:
            replacement = item.value
        replacements.append((item.start, item.end, replacement))

    transformed = text
    if mode != "detection":
        for start, end, replacement in reversed(replacements):
            transformed = transformed[:start] + replacement + transformed[end:]

    warnings = (
        "Rule-based local detection was used; a privacy reviewer must confirm that no unsupported identifiers remain.",
    )
    return DeidentificationResult(
        text=transformed,
        mode=mode,
        findings=tuple(findings),
        counts=counts,
        review_required=True,
        warnings=warnings,
    )

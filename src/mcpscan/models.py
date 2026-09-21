"""Core data types shared by rules, scanner and reporters."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field as dc_field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {names})") from None

    @property
    def label(self) -> str:
        return self.name.lower()


# Categories that must never reach a terminal or report verbatim: control
# characters (incl. ANSI escapes), format characters, private use, unassigned
# and surrogates. Scanned files are untrusted input.
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cn", "Cs"})
_ZWJ = "‍"


def clean_text(text: str, limit: int = 200) -> str:
    """Collapse whitespace, escape invisible/control characters, and truncate."""
    collapsed = " ".join(text.split())
    out = []
    for ch in collapsed:
        if ch != _ZWJ and unicodedata.category(ch) in _ESCAPED_CATEGORIES:
            out.append(f"<U+{ord(ch):04X}>")
        else:
            out.append(ch)
    result = "".join(out)
    if len(result) > limit:
        result = result[: limit - 1] + "…"
    return result


def snippet(text: str, start: int, end: int, context: int = 40) -> str:
    """Return the matched span with a little surrounding context, cleaned."""
    lo = max(0, start - context)
    hi = min(len(text), end + context)
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) else ""
    return clean_text(prefix + text[lo:hi] + suffix)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    subject: str  # what was flagged, e.g. "tool:read_file" or "server:github"
    field: str  # where inside the subject, e.g. "description"; may be empty
    evidence: str
    remediation: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject", clean_text(self.subject, 120))
        object.__setattr__(self, "field", clean_text(self.field, 120))
        object.__setattr__(self, "evidence", clean_text(self.evidence, 240))

    def sort_key(self) -> Tuple[Any, ...]:
        return (-int(self.severity), self.rule_id, self.subject, self.field, self.evidence, self.title)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "title": self.title,
            "subject": self.subject,
            "field": self.field,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class Suppressed:
    """A finding hidden by an ignore rule or the baseline; counted, never silently dropped."""

    finding: Finding
    source: str  # "ignore" or "baseline"
    reason: str


@dataclass
class ScanResult:
    path: str
    input_type: str  # "manifest", "config" or "manifest+config"
    findings: List[Finding]  # active findings only; these drive the exit code
    tool_count: int = 0
    server_count: int = 0
    suppressed: List[Suppressed] = dc_field(default_factory=list)
    stale_baseline: int = 0  # baseline entries that no longer match any finding
    # Raw file text, kept so SARIF can point at real line numbers. Not part of equality or repr.
    source_text: Optional[str] = dc_field(default=None, repr=False, compare=False)

    def counts(self) -> Dict[str, int]:
        counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def exceeds(self, threshold: Severity) -> bool:
        return any(f.severity >= threshold for f in self.findings)

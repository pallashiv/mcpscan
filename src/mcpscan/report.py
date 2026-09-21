"""Renderers: text (optionally colored), JSON, Markdown and SARIF 2.1.0."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .models import Finding, ScanResult, Severity
from .rules import RULE_INFO

_COLORS = {
    Severity.CRITICAL: "\x1b[1;95m",
    Severity.HIGH: "\x1b[31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
}
_DIM, _RESET = "\x1b[2m", "\x1b[0m"

_INPUT_LABELS = {"manifest": "tool manifest", "config": "client config", "manifest+config": "manifest + config"}


def _suppression_note(result: ScanResult) -> str:
    if not result.suppressed:
        return ""
    by_source = {"baseline": 0, "ignore": 0}
    for s in result.suppressed:
        by_source[s.source] += 1
    parts = []
    if by_source["baseline"]:
        parts.append(f"{by_source['baseline']} in baseline")
    if by_source["ignore"]:
        parts.append(f"{by_source['ignore']} ignored")
    return f"{len(result.suppressed)} suppressed: {', '.join(parts)}"


def _summary_line(result: ScanResult) -> str:
    note = _suppression_note(result)
    if not result.findings:
        if result.input_type == "config" and result.server_count == 0:
            line = "No MCP servers configured; nothing to scan."
        else:
            line = "No findings"
            line += f" ({note})." if note else "."
    else:
        parts = [f"{n} {label}" for label, n in result.counts().items() if n]
        total = len(result.findings)
        line = f"{total} finding{'s' if total != 1 else ''} ({', '.join(parts)})"
        if note:
            line += f"; {note}"
    if result.stale_baseline:
        n = result.stale_baseline
        line += f"\nBaseline has {n} stale entr{'ies' if n != 1 else 'y'} (fixed or renamed); regenerate it with --write-baseline."
    return line


def _scanned(result: ScanResult) -> str:
    bits = []
    if result.input_type.startswith("manifest"):
        bits.append(f"{result.tool_count} tool{'s' if result.tool_count != 1 else ''}")
    if result.input_type.endswith("config"):
        bits.append(f"{result.server_count} server{'s' if result.server_count != 1 else ''}")
    return ", ".join(bits)


def render_text(result: ScanResult, color: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    kind = _INPUT_LABELS.get(result.input_type, result.input_type)
    lines = [f"mcpscan {__version__}: {result.path} ({kind}; {_scanned(result)})", ""]
    for f in result.findings:
        where = f.subject + (f"  {f.field}" if f.field else "")
        lines.append(f"{paint(f.severity.name.ljust(8), _COLORS[f.severity])} {f.rule_id}  {where}")
        lines.append(f"    {f.title}")
        lines.append(f"    {paint('evidence:', _DIM)} {f.evidence}")
        lines.append(f"    {paint('fix:', _DIM)}      {f.remediation}")
        lines.append("")
    lines.append(_summary_line(result))
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    doc: Dict[str, Any] = {
        "tool": "mcpscan",
        "version": __version__,
        "path": result.path,
        "input_type": result.input_type,
        "tools_scanned": result.tool_count,
        "servers_scanned": result.server_count,
        "summary": {"total": len(result.findings), **result.counts(), "suppressed": len(result.suppressed)},
        "stale_baseline_entries": result.stale_baseline,
        "findings": [f.to_dict() for f in result.findings],
        "suppressed": [
            {**s.finding.to_dict(), "suppressed_by": s.source, "reason": s.reason} for s in result.suppressed
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def _fence_for(text: str, minimum: int) -> str:
    longest = run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return "`" * max(minimum, longest + 1)


def _inline(text: str) -> str:
    fence = _fence_for(text, 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _block(text: str) -> str:
    fence = _fence_for(text, 3)
    return f"{fence}\n{text}\n{fence}"


def render_markdown(result: ScanResult) -> str:
    kind = _INPUT_LABELS.get(result.input_type, result.input_type)
    lines = [
        "# mcpscan report",
        "",
        f"- **Input:** {_inline(result.path)} ({kind})",
        f"- **Scanned:** {_scanned(result)}",
        f"- **Result:** {_summary_line(result)}",
        "",
    ]
    if result.findings:
        lines += ["| Severity | Count |", "| --- | ---: |"]
        lines += [f"| {label} | {n} |" for label, n in result.counts().items()]
        lines += ["", "## Findings", ""]
    for f in result.findings:
        where = _inline(f.subject) + (f" › {_inline(f.field)}" if f.field else "")
        lines += [
            f"### {f.severity.name} · {f.rule_id} · {f.title}",
            "",
            f"- **Where:** {where}",
            f"- **Fix:** {f.remediation}",
            "",
            "Evidence:",
            "",
            _block(f.evidence),
            "",
        ]
    return "\n".join(lines).rstrip("\n") + "\n"


_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.0", Severity.LOW: "2.0"}


def _artifact_uri(path: str) -> str:
    p = Path(path)
    return p.as_uri() if p.is_absolute() else p.as_posix()


def render_sarif(result: ScanResult) -> str:
    rule_ids = sorted(RULE_INFO)
    rules: List[Dict[str, Any]] = []
    for rid in rule_ids:
        info = RULE_INFO[rid]
        top = max(info.severities)
        rules.append({
            "id": rid,
            "name": info.name,
            "shortDescription": {"text": info.name},
            "fullDescription": {"text": info.summary},
            "help": {"text": info.remediation},
            "defaultConfiguration": {"level": _SARIF_LEVEL[top]},
            "properties": {"tags": ["security", "mcp"], "security-severity": _SECURITY_SEVERITY[top]},
        })
    results: List[Dict[str, Any]] = []
    for f in result.findings:
        results.append(_sarif_result(f, result.path, rule_ids.index(f.rule_id), result.source_text))
    for s in result.suppressed:
        entry = _sarif_result(s.finding, result.path, rule_ids.index(s.finding.rule_id), result.source_text)
        entry["suppressions"] = [{"kind": "external", "justification": s.reason}]
        results.append(entry)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "mcpscan", "version": __version__, "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def locate(text: Optional[str], subject: str) -> int:
    """Best-effort 1-based line of a subject ("tool:x", "server:x") in the source JSON; 1 if unknown."""
    kind, _, name = subject.partition(":")
    if not text or kind not in ("tool", "server") or not name:
        return 1
    for needle in (json.dumps(name, ensure_ascii=False), json.dumps(name)):
        if kind == "tool":
            pattern = re.compile(r'"name"\s*:\s*' + re.escape(needle))
        else:
            pattern = re.compile(re.escape(needle) + r"\s*:")
        m = pattern.search(text)
        if m:
            return text.count("\n", 0, m.start()) + 1
    return 1


def _fingerprint(f: Finding) -> str:
    """Stable identity for code scanning. Excludes evidence so rewording does not reopen alerts."""
    key = "\0".join((f.rule_id, f.subject, f.field, f.title))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def _sarif_result(f: Finding, path: str, rule_index: int, text: Optional[str] = None) -> Dict[str, Any]:
    where = f.subject + (f" {f.field}" if f.field else "")
    return {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.title} ({where}): {f.evidence}. {f.remediation}"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": _artifact_uri(path)},
                "region": {"startLine": locate(text, f.subject)},
            },
            "logicalLocations": [{"name": f.subject, "fullyQualifiedName": f"{f.subject}/{f.field}" if f.field else f.subject}],
        }],
        "partialFingerprints": {"mcpscan/finding/v1": _fingerprint(f)},
        "properties": {"severity": f.severity.label},
    }


RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "sarif": render_sarif,
}

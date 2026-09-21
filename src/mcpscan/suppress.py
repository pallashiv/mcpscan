"""Baseline and ignore files: hide known findings so CI fails only on new ones.

Both are plain JSON (stdlib only). Suppressed findings are kept on the result and
reported as a count, never dropped silently.

Matching uses (rule_id, subject, field, title), not the evidence text, so small
wording changes in a tool description do not resurface an accepted finding.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import replace
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

from .models import Finding, ScanResult, Suppressed
from .rules import RULE_INFO
from .scanner import ScanError

BASELINE_FORMAT = 1
Key = Tuple[str, str, str, str]


class SuppressError(ScanError):
    """A baseline or ignore file is unreadable or malformed."""


class IgnoreRule(NamedTuple):
    rule: str
    subject: str  # fnmatch glob, "*" = any
    field: str  # fnmatch glob, "*" = any
    reason: str


def finding_key(f: Finding) -> Key:
    return (f.rule_id, f.subject, f.field, f.title)


def _load_json(path: str, what: str) -> Any:
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise SuppressError(f"{what} not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise SuppressError(f"cannot read {what} {path}: {exc}") from None
    except (json.JSONDecodeError, RecursionError) as exc:
        raise SuppressError(f"{what} {path} is not valid JSON: {exc}") from None


# Baseline -------------------------------------------------------------------


def baseline_document(findings: Iterable[Finding]) -> str:
    entries = sorted({finding_key(f) for f in findings})
    doc = {
        "format": BASELINE_FORMAT,
        "findings": [{"rule_id": r, "subject": s, "field": fld, "title": t} for r, s, fld, t in entries],
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def load_baseline(path: str) -> Set[Key]:
    doc = _load_json(path, "baseline")
    if not isinstance(doc, dict) or doc.get("format") != BASELINE_FORMAT or not isinstance(doc.get("findings"), list):
        raise SuppressError(f"{path} is not an mcpscan baseline (expected format {BASELINE_FORMAT}; create one with --write-baseline)")
    keys: Set[Key] = set()
    for i, entry in enumerate(doc["findings"]):
        fields = ("rule_id", "subject", "field", "title")
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in fields):
            raise SuppressError(f"{path}: findings[{i}] must have string keys {', '.join(fields)}")
        keys.add(tuple(entry[k] for k in fields))  # type: ignore[arg-type]
    return keys


# Ignore file ----------------------------------------------------------------

_IGNORE_KEYS = {"rule", "subject", "field", "reason"}


def load_ignore(path: str) -> List[IgnoreRule]:
    doc = _load_json(path, "ignore file")
    if not isinstance(doc, dict) or not isinstance(doc.get("ignore"), list):
        raise SuppressError(f'{path}: expected {{"ignore": [{{"rule": ..., "reason": ...}}, ...]}}')
    rules: List[IgnoreRule] = []
    for i, entry in enumerate(doc["ignore"]):
        where = f"{path}: ignore[{i}]"
        if not isinstance(entry, dict):
            raise SuppressError(f"{where} must be an object")
        unknown = set(entry) - _IGNORE_KEYS
        if unknown:
            raise SuppressError(f"{where} has unknown key(s): {', '.join(sorted(unknown))} (allowed: {', '.join(sorted(_IGNORE_KEYS))})")
        rule = entry.get("rule")
        if not isinstance(rule, str) or rule.upper() not in RULE_INFO:
            raise SuppressError(f"{where}: 'rule' must be a known rule ID such as MCP005")
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise SuppressError(f"{where}: a non-empty 'reason' is required so suppressions stay reviewable")
        patterns = []
        for key in ("subject", "field"):
            value = entry.get(key, "*")
            if not isinstance(value, str) or not value:
                raise SuppressError(f"{where}: '{key}' must be a non-empty glob string")
            patterns.append(value)
        rules.append(IgnoreRule(rule.upper(), patterns[0], patterns[1], reason.strip()))
    return rules


def _ignored_by(f: Finding, rules: List[IgnoreRule]) -> Optional[IgnoreRule]:
    for r in rules:
        if (
            r.rule == f.rule_id
            and fnmatch.fnmatchcase(f.subject, r.subject)
            and fnmatch.fnmatchcase(f.field, r.field)
        ):
            return r
    return None


# Applying -------------------------------------------------------------------


def apply_suppressions(
    result: ScanResult,
    ignore: Optional[List[IgnoreRule]] = None,
    baseline: Optional[Set[Key]] = None,
) -> ScanResult:
    """Split findings into active and suppressed. Ignore rules win over the baseline."""
    active: List[Finding] = []
    suppressed: List[Suppressed] = []
    for f in result.findings:
        rule = _ignored_by(f, ignore) if ignore else None
        if rule is not None:
            suppressed.append(Suppressed(f, "ignore", rule.reason))
        elif baseline is not None and finding_key(f) in baseline:
            suppressed.append(Suppressed(f, "baseline", "listed in baseline"))
        else:
            active.append(f)
    stale = 0
    if baseline is not None:
        stale = len(baseline - {finding_key(f) for f in result.findings})
    suppressed.sort(key=lambda s: s.finding.sort_key())
    return replace(result, findings=active, suppressed=suppressed, stale_baseline=stale)

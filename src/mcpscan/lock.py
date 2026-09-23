"""Rug-pull detection: fingerprint each tool's declaration and flag drift on later scans.

A server that looked safe when its tools were reviewed can change a tool's description or
schema afterwards - tool poisoning delivered after approval rather than at install time.
mcpscan cannot watch a server continuously (v0.1 is static analysis only, over one file), but a
lock file recorded at approval time lets every later scan catch drift: a tool that is new,
missing, or whose declaration no longer matches what was approved.

Lock findings are ordinary Findings (rule ids LOCK001-003, defined in rules.RULE_INFO), so they
flow through the same severity, ignore-file, baseline and report machinery as every other rule.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from .models import Finding, snippet
from .rules import H, L, M, RULE_INFO
from .scanner import ScanError

LOCK_FORMAT = 1


class LockError(ScanError):
    """A lock file is unreadable or malformed."""


def fingerprint(tool: Dict[str, Any]) -> str:
    """A stable hash of the parts of a tool declaration a client actually acts on.

    The tool's position in the list and any extra fields a server happens to add are not part
    of a client's behaviour, so they are excluded - a fingerprint changes only when something
    that could change what the model sees or is allowed to do changes.
    """
    material = {
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
        "annotations": tool.get("annotations"),
    }
    canonical = json.dumps(material, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _tool_names(tools: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    named: Dict[str, Dict[str, Any]] = {}
    for tool in tools:
        name = tool.get("name")
        if isinstance(name, str) and name:
            named[name] = tool  # last one wins on a duplicate name; MCP008 flags duplicates separately
    return named


def lock_document(tools: List[Dict[str, Any]]) -> str:
    entries = {name: fingerprint(tool) for name, tool in sorted(_tool_names(tools).items())}
    doc = {"format": LOCK_FORMAT, "tools": entries}
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def load_lock(path: str) -> Dict[str, str]:
    try:
        with open(path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise LockError(f"lock file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise LockError(f"cannot read lock file {path}: {exc}") from None
    except (json.JSONDecodeError, RecursionError) as exc:
        raise LockError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(doc, dict) or doc.get("format") != LOCK_FORMAT or not isinstance(doc.get("tools"), dict):
        raise LockError(f"{path} is not an mcpscan lock file (expected format {LOCK_FORMAT}; create one with --write-lock)")
    tools = doc["tools"]
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in tools.items()):
        raise LockError(f"{path}: 'tools' must map tool names to hash strings")
    return tools


def _finding(rule_id: str, name: str, evidence: str) -> Finding:
    info = RULE_INFO[rule_id]
    severity = info.severities[0]
    return Finding(rule_id, severity, info.name, f"tool:{name}", "", evidence, info.remediation)


def check_lock(tools: Optional[List[Dict[str, Any]]], lock: Dict[str, str]) -> List[Finding]:
    """Compare the current tools against a previously written lock. See module docstring."""
    current = _tool_names(tools or [])
    out: List[Finding] = []

    for name in sorted(current):
        tool = current[name]
        if name not in lock:
            out.append(_finding("LOCK002", name, f"'{name}' is not in the lock file: a new tool, or renamed from one that was"))
        elif lock[name] != fingerprint(tool):
            desc = tool.get("description")
            desc_text = desc if isinstance(desc, str) else "<no description>"
            out.append(_finding(
                "LOCK001", name,
                f"'{name}' no longer matches its locked declaration; current description: "
                + snippet(desc_text, 0, len(desc_text)),
            ))
    for name in sorted(set(lock) - set(current)):
        out.append(_finding("LOCK003", name, f"'{name}' is in the lock file but the server no longer offers it"))
    return out

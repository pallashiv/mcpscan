"""Input detection and rule orchestration. Reads a file; never runs or connects to anything."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Finding, ScanResult
from .rules import CONFIG_RULES, MANIFEST_RULES


class ScanError(Exception):
    """The input could not be read or is not a recognised MCP file."""


def _find_servers(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for candidate in (data.get("mcpServers"), data.get("servers")):
        if candidate is not None:
            if not isinstance(candidate, dict):
                raise ScanError("'mcpServers' must be an object mapping server names to configs")
            return candidate
    nested = data.get("mcp")  # VS Code settings.json
    if isinstance(nested, dict) and isinstance(nested.get("servers"), dict):
        return nested["servers"]
    return None


def _find_tools(data: Any) -> Optional[List[Dict[str, Any]]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "tools" in data:
            tools = data["tools"]
        elif isinstance(data.get("result"), dict) and "tools" in data["result"]:
            tools = data["result"]["tools"]  # raw JSON-RPC tools/list response
        else:
            return None
        if not isinstance(tools, list):
            raise ScanError("'tools' must be a list")
        return tools
    return None


def scan_data(data: Any, source: str = "<data>") -> ScanResult:
    servers = _find_servers(data) if isinstance(data, dict) else None
    tools = _find_tools(data)
    if servers is None and tools is None:
        raise ScanError(
            "unrecognised input: expected a tool manifest ({\"tools\": [...]} or a list) "
            "or a client config ({\"mcpServers\": {...}})"
        )

    findings: List[Finding] = []
    kinds = []
    tool_count = server_count = 0
    if tools is not None:
        for i, tool in enumerate(tools):
            if not isinstance(tool, dict):
                raise ScanError(f"tools[{i}] is not an object")
        kinds.append("manifest")
        tool_count = len(tools)
        for rule in MANIFEST_RULES:
            findings.extend(rule(tools))
    if servers is not None:
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                raise ScanError(f"server {name!r} config is not an object")
        kinds.append("config")
        server_count = len(servers)
        for rule in CONFIG_RULES:
            findings.extend(rule(servers))

    unique = sorted(set(findings), key=Finding.sort_key)
    return ScanResult(source, "+".join(kinds), unique, tool_count, server_count)


def scan_file(path: str) -> ScanResult:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise ScanError(f"file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise ScanError(f"cannot read {path}: {exc}") from None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ScanError(f"{path} is not valid JSON: {exc}") from None
    return scan_data(data, path)

"""Detection rules.

Pure functions over already-parsed JSON: no I/O, no network, nothing executed.
Manifest rules take the list of tool dicts; config rules take the
``{server_name: server_config}`` mapping. Each returns a list of Findings.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any, Callable, Dict, Iterable, Iterator, List, NamedTuple, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from .models import Finding, Severity, snippet

L, M, H, C = Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL


class RuleInfo(NamedTuple):
    rule_id: str
    name: str
    severities: Tuple[Severity, ...]
    summary: str
    remediation: str


RULE_INFO: Dict[str, RuleInfo] = {
    r.rule_id: r
    for r in (
        RuleInfo(
            "MCP001", "Tool poisoning / prompt injection", (C, H, M),
            "Instructions aimed at the model hidden in a tool's name, description or schema text.",
            "Remove model-directed instructions from tool metadata. Metadata should describe what "
            "the tool does and nothing else; do not install tools from untrusted sources.",
        ),
        RuleInfo(
            "MCP002", "Invisible Unicode in metadata", (H,),
            "Zero-width, tag, private-use or unassigned characters in tool metadata that hide "
            "content from human reviewers.",
            "Strip invisible characters from tool metadata and investigate how they got there.",
        ),
        RuleInfo(
            "MCP003", "Sensitive file reference", (H, M),
            "Tool metadata mentions credential or secret files (~/.ssh, .env, .aws/credentials, ...).",
            "Tools should not reference credential files. If access is legitimate, document it "
            "outside model-visible metadata and scope it tightly.",
        ),
        RuleInfo(
            "MCP004", "Over-permissioned capability", (H, M),
            "Command execution, filesystem write/delete, raw SQL, arbitrary URL fetch, secret "
            "access or outbound messaging.",
            "Offer narrow, purpose-specific tools instead of general primitives, and require "
            "human confirmation for the risky ones.",
        ),
        RuleInfo(
            "MCP005", "Weak input schema", (M, L),
            "Free-form string for a risky parameter (command, sql, script: per tool, medium; path, "
            "url, host: once per manifest, low), missing input schema, or additionalProperties not "
            "set to false (once per manifest).",
            "Constrain risky string parameters with enum, pattern or maxLength, declare an "
            "inputSchema, and set additionalProperties to false.",
        ),
        RuleInfo(
            "MCP006", "Missing tool annotations", (L,),
            "State-changing tool declares neither readOnlyHint nor destructiveHint.",
            "Set readOnlyHint and destructiveHint in the tool's annotations so clients can "
            "prompt appropriately.",
        ),
        RuleInfo(
            "MCP007", "Cross-tool reference (shadowing)", (M, L),
            "A description refers to another tool (low, once per manifest: usually workflow guidance), "
            "or steers the model away from other tools (medium).",
            "Tool descriptions should be self-contained. If a reference is only workflow guidance it is "
            "harmless; references that redirect the model away from other tools are not.",
        ),
        RuleInfo(
            "MCP008", "Duplicate tool name", (M,),
            "Two tools share a name (or differ only by case or -/_), so one can shadow the other.",
            "Give every tool a unique, unambiguous name.",
        ),
        RuleInfo(
            "CFG001", "Hardcoded secret", (H,),
            "API key, token or password written directly into env, headers, args or a URL.",
            "Reference secrets from the environment or a secret store (e.g. ${VAR}) and rotate "
            "any secret that has been committed.",
        ),
        RuleInfo(
            "CFG002", "Plaintext HTTP remote server", (H,),
            "Remote MCP server reached over http:// or ws:// on a non-local host.",
            "Use https:// (or wss://) for every non-local server.",
        ),
        RuleInfo(
            "CFG003", "Remote server without visible auth", (M,),
            "Remote MCP server with no auth header, credential or OAuth setting in the config.",
            "Configure authentication. If the server uses OAuth handled by the client, this "
            "finding can be ignored.",
        ),
        RuleInfo(
            "CFG004", "Unpinned package", (M,),
            "Server launched through npx/uvx/pipx without an exact version.",
            "Pin an exact version (pkg@1.2.3 or pkg==1.2.3) so upgrades are deliberate and "
            "reviewed.",
        ),
        RuleInfo(
            "CFG005", "Launched via shell or curl|sh", (H, M),
            "Server command runs through a shell, or pipes a download into one.",
            "Launch the server binary directly with an argument list instead of a shell string.",
        ),
        RuleInfo(
            "CFG006", "Overly broad filesystem root", (H,),
            "Server granted access to /, ~ or a whole home directory.",
            "Grant only the specific project directories the server needs.",
        ),
    )
}


def _finding(
    rule_id: str,
    severity: Severity,
    subject: str,
    field: str,
    evidence: str,
    title: Optional[str] = None,
) -> Finding:
    info = RULE_INFO[rule_id]
    return Finding(rule_id, severity, title or info.name, subject, field, evidence, info.remediation)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

_MAX_DEPTH = 64
_PLAIN_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def iter_text(obj: Any, path: str = "", include_keys: bool = True, _depth: int = 0) -> Iterator[Tuple[str, str]]:
    """Yield (field_path, text) for every string in a JSON value, keys included.

    Plain identifier keys ("type", "path") are skipped: they cannot carry
    instructions and would only add noise.
    """
    if _depth > _MAX_DEPTH:
        return
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k)
            child = f"{path}.{key}" if path else key
            if include_keys and not _PLAIN_KEY.match(key):
                yield f"{child} (key)", key
            yield from iter_text(v, child, include_keys, _depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from iter_text(v, f"{path}[{i}]", include_keys, _depth + 1)


def tool_name(tool: Dict[str, Any], index: int) -> str:
    name = tool.get("name")
    return name if isinstance(name, str) and name else f"<unnamed #{index}>"


def _norm(name: str) -> str:
    """camelCase / kebab-case / spaces -> snake_case, lowercase."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return re.sub(r"[^a-z0-9]+", "_", spaced.lower()).strip("_")


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _input_schema(tool: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    schema = tool.get("inputSchema")
    return schema if isinstance(schema, dict) else None


def _rx(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.IGNORECASE)


# --------------------------------------------------------------------------- #
# MCP001: tool poisoning / prompt injection
# --------------------------------------------------------------------------- #

_INJECTION: Tuple[Tuple[str, Severity, "re.Pattern[str]"], ...] = (
    (
        "Hidden instruction tag in tool metadata", C,
        _rx(r"<\s*/?\s*(?:important|system|instructions?|secret|hidden|admin|override)\s*>"),
    ),
    (
        "Instruction to conceal actions from the user", C,
        _rx(r"\b(?:do not|don't|never|without)\b[^.\n]{0,30}\b(?:tell|inform|mention|notify|alert|show|reveal|disclose|let)\b[^.\n]{0,30}\buser\b"),
    ),
    (
        "Instruction to conceal actions from the user", C,
        _rx(r"\buser\s+(?:must not|should not|shouldn't|mustn't|cannot|can't)\s+(?:see|know|be (?:told|aware|notified))"),
    ),
    ("Exfiltration directive in tool metadata", C, _rx(r"\bexfiltrat\w*")),
    (
        "Exfiltration directive in tool metadata", C,
        _rx(
            r"\b(?:send|post|forward|upload|transmit|email|leak)\b[^.\n]{0,60}"
            r"\b(?:conversation|chat history|system prompt|previous messages|credentials|passwords?|api[ _-]?keys?|secrets?|private keys?|ssh keys?)\b"
            r"[^.\n]{0,60}\b(?:to|at)\b[^.\n]{0,40}(?:https?://|\S+@\S+\.\S+)"
        ),
    ),
    (
        "Instruction override in tool metadata", H,
        _rx(r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any)\b[^.\n]{0,30}\b(?:instructions?|prompts?|rules|directions?)\b"),
    ),
    (
        "Injected instructions block in tool metadata", H,
        _rx(r"\b(?:new|updated|additional|real|actual|secret)\s+instructions?\s*:"),
    ),
    (
        # Sequencing ("call resolve-id first") is common in legitimate servers, and "this tool"
        # is the tool itself, so this stays at MEDIUM and never fires on "call this tool".
        "Forced tool call in tool metadata", M,
        _rx(r"\b(?:you (?:must|should|need to)|always|first)\b[^.\n]{0,40}\b(?:call|invoke|execute)\s+(?!this\b|the same\b)[^.\n]{0,40}\b(?:tool|function)\b"),
    ),
)


def check_mcp001(tools: List[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    for i, tool in enumerate(tools):
        subject = f"tool:{tool_name(tool, i)}"
        seen = set()
        for field, text in iter_text(tool):
            for title, severity, rx in _INJECTION:
                if title in seen:
                    continue
                m = rx.search(text)
                if m:
                    seen.add(title)
                    out.append(_finding("MCP001", severity, subject, field, snippet(text, m.start(), m.end()), title))
    return out


# --------------------------------------------------------------------------- #
# MCP002: invisible Unicode
# --------------------------------------------------------------------------- #

_INVISIBLE_CATEGORIES = frozenset({"Cf", "Co", "Cn", "Cs"})
_ALLOWED_INVISIBLE = frozenset({"‍"})  # zero-width joiner: legitimate in emoji sequences


def _char_label(ch: str) -> str:
    return f"U+{ord(ch):04X} ({unicodedata.name(ch, 'unassigned or private use')})"


def check_mcp002(tools: List[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    for i, tool in enumerate(tools):
        subject = f"tool:{tool_name(tool, i)}"
        for field, text in iter_text(tool):
            hits = [
                (pos, ch)
                for pos, ch in enumerate(text)
                if ch not in _ALLOWED_INVISIBLE and unicodedata.category(ch) in _INVISIBLE_CATEGORIES
            ]
            if not hits:
                continue
            distinct = sorted({ch for _, ch in hits})
            listed = ", ".join(_char_label(ch) for ch in distinct[:4])
            more = f" and {len(distinct) - 4} more" if len(distinct) > 4 else ""
            first = hits[0][0]
            evidence = f"{len(hits)} invisible character(s): {listed}{more}; near: {snippet(text, first, first + 1, 30)}"
            out.append(_finding("MCP002", H, subject, field, evidence))
    return out


# --------------------------------------------------------------------------- #
# MCP003: sensitive file references
# --------------------------------------------------------------------------- #

# .env and generic "credentials.json" names show up in ordinary dev-tool docs (search examples,
# "loads .env"), so they are MEDIUM. Files that only ever hold secrets stay HIGH.
_SENSITIVE_FILES: Tuple[Tuple[str, Severity, "re.Pattern[str]"], ...] = (
    ("SSH keys or config", H, _rx(r"(?<![\w])\.ssh\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b")),
    ("dotenv file", M, _rx(r"(?<![\w])\.env(?:\.[\w-]+)?\b")),
    ("AWS credentials", H, _rx(r"(?<![\w])\.aws\b(?:/\w+)?|\baws_secret_access_key\b")),
    ("package registry credentials", H, _rx(r"(?<![\w])\.(?:npmrc|pypirc|netrc|git-credentials)\b")),
    ("cloud/CLI config", H, _rx(r"(?<![\w])\.(?:kube/config|docker/config\.json|config/gcloud|azure)\b")),
    ("GPG keyring", H, _rx(r"(?<![\w])\.gnupg\b")),
    ("system password files", H, _rx(r"/etc/(?:passwd|shadow|sudoers)\b")),
    ("shell history", H, _rx(r"(?<![\w])\.(?:bash|zsh)_history\b")),
    ("credentials file", M, _rx(r"\b(?:credentials|secrets?)\.(?:json|ya?ml)\b")),
    ("OS keychain", H, _rx(r"Library/Keychains|\bkeychain\b")),
)


def check_mcp003(tools: List[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    for i, tool in enumerate(tools):
        subject = f"tool:{tool_name(tool, i)}"
        seen = set()
        for field, text in iter_text(tool):
            for label, severity, rx in _SENSITIVE_FILES:
                if label in seen:
                    continue
                m = rx.search(text)
                if m:
                    seen.add(label)
                    out.append(_finding("MCP003", severity, subject, field, snippet(text, m.start(), m.end()), f"Reference to sensitive file: {label}"))
    return out


# --------------------------------------------------------------------------- #
# MCP004: over-permissioned capability
# --------------------------------------------------------------------------- #


class _Capability(NamedTuple):
    label: str
    severity: Severity
    name: "re.Pattern[str]"
    desc: "re.Pattern[str]"
    param: Optional["re.Pattern[str]"]


_CAPABILITIES: Tuple[_Capability, ...] = (
    _Capability(
        "command execution", H,
        _rx(r"(?:^|_)(?:exec|execute|run|start|spawn|launch)_(?:command|cmd|shell|bash|script|code|process|terminal|subprocess)(?:_|$)|(?:^|_)(?:shell|bash|powershell|terminal|subprocess|eval)(?:_|$)|^(?:exec|execute|run)$"),
        _rx(r"\b(?:execut\w*|run\w*)\s+(?:an?\s+|any\s+|arbitrary\s+|the\s+)?(?:shell|bash|system|terminal|os)\s+(?:commands?|scripts?|code)\b|\bexecut\w*\s+(?:any|arbitrary)\s+\w+"),
        _rx(r"(?:command|cmd|shell_command|command_line|commandline|bash|shell)\Z"),
    ),
    _Capability(
        "filesystem write/delete", M,
        _rx(r"(?:^|_)(?:write|delete|remove|overwrite|rename|move|truncate|chmod|chown|mkdir|rmdir|unlink|append|edit|create)_(?:file|files|dir|directory|folder|path)s?(?:_|$)|(?:^|_)(?:file|directory|dir|folder)_(?:write|delete|remove|overwrite|move)(?:_|$)|^(?:rm|unlink|rmdir)$"),
        _rx(r"\b(?:writes?|overwrit\w+|deletes?|removes?|modif(?:y|ies))\b[^.\n]{0,25}\b(?:files?|director(?:y|ies)|folders?)\b"),
        None,
    ),
    _Capability(
        "raw SQL execution", H,
        _rx(r"(?:^|_)sql(?:_|$)|(?:^|_)(?:raw|run|execute|exec)_(?:query|statement)s?(?:_|$)"),
        _rx(r"\b(?:raw|arbitrary|any)\s+sql\b|\bexecut\w*\s+(?:an?\s+|any\s+|arbitrary\s+)?(?:sql|queries|statements)\b|\brun\s+(?:an?\s+|any\s+|arbitrary\s+)?sql\b"),
        _rx(r"(?:sql|raw_sql|sql_query|statement|sql_statement|raw_query)\Z"),
    ),
    _Capability(
        "arbitrary URL fetch", M,
        _rx(r"^(?:fetch|fetch_url|fetch_page|fetch_webpage|web_fetch|http_request|http_get|http_post|curl|wget|download|download_file|download_url|scrape|scrape_url|browse|browse_url|open_url|request)$|(?:^|_)(?:fetch|download|scrape|browse|open)_(?:url|uri|page|webpage|website|link)s?$|(?:^|_)http_(?:request|get|post|fetch)(?:_|$)"),
        _rx(r"\b(?:fetch|retrieve|download|request|get|visit|open|browse)(?:e?s)?\b[^.\n]{0,20}\b(?:any|arbitrary|a given|the given|specified|provided|user-supplied)\s+(?:url|uri|web ?page|website|link|http endpoint)s?\b"),
        None,
    ),
    _Capability(
        "secret access", H,
        _rx(r"(?:^|_)(?:get|read|list|dump|fetch|retrieve|show|reveal|export|access)_(?:\w+_)?(?:secrets?|credentials?|passwords?|api_keys?|keychain|env|env_vars?|environment_variables?)(?:_|$)|(?:^|_)(?:secret|secrets|keychain|vault)_(?:get|read|list|dump)(?:_|$)|^(?:getenv|get_env|printenv)$"),
        _rx(r"\b(?:reads?|gets?|retrieves?|lists?|dumps?|accesses|exports?|returns?|fetch(?:es)?)\b[^.\n]{0,30}\b(?:secrets?|credentials?|passwords?|api[ _-]?keys?|(?:access|auth|bearer|session) tokens?|environment variables?|env vars?|private keys?)\b"),
        None,
    ),
    _Capability(
        "outbound messaging", M,
        _rx(r"(?:^|_)(?:send|post|publish|reply)_(?:an_)?(?:email|mail|message|sms|text|dm|notification|slack|tweet|whatsapp|telegram|comment)s?(?:_|$)|^(?:sendmail|tweet|notify|email|sms)$"),
        _rx(r"\b(?:sends?|posts?|publish(?:es)?)\b[^.\n]{0,25}\b(?:e-?mails?|messages?|sms|texts?|tweets?|slack|notifications?)\b"),
        None,
    ),
)

_BROAD = _rx(
    r"\b(?:arbitrary|unrestricted|any (?:file|path|director\w+|url|command|sql|query|statement|script)"
    r"|anywhere|without (?:any )?(?:restrictions?|validation|sandbox\w*|limits?))\b"
)


def _param_names(tool: Dict[str, Any]) -> List[str]:
    schema = _input_schema(tool)
    props = schema.get("properties") if schema else None
    return [str(k) for k in props] if isinstance(props, dict) else []


_NEGATION = re.compile(r"\b(?:never|not|don'?t|do not|avoid|without|cannot|can'?t)\b[^.\n]*\Z", re.IGNORECASE)


def _first_affirmative(rx: "re.Pattern[str]", text: str) -> "Optional[re.Match[str]]":
    """First match that is not negated: "NEVER overwrite the original file" is a warning, not a capability."""
    for m in rx.finditer(text):
        if not _NEGATION.search(text[max(0, m.start() - 25) : m.start()]):
            return m
    return None


def check_mcp004(tools: List[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    for i, tool in enumerate(tools):
        name = tool_name(tool, i)
        norm = _norm(name)
        desc = _str(tool.get("description"))
        params = _param_names(tool)
        broad = _BROAD.search(desc)
        for cap in _CAPABILITIES:
            severity = cap.severity
            field = ""
            if cap.name.search(norm):
                field, evidence = "name", f"tool name '{name}'"
            else:
                m = _first_affirmative(cap.desc, desc)
                if m:
                    field, evidence = "description", snippet(desc, m.start(), m.end())
                else:
                    hit = next((p for p in params if cap.param and cap.param.match(_norm(p))), None)
                    if hit is None:
                        continue
                    # A parameter name alone is weaker evidence: drop one level.
                    field, evidence = "inputSchema", f"parameter '{hit}'"
                    severity = Severity(max(int(L), int(severity) - 1))
            if broad and field != "inputSchema" and severity < H:
                severity = Severity(min(int(H), int(severity) + 1))
                evidence += f" (raised: description says '{broad.group(0)}')"
            out.append(_finding("MCP004", severity, f"tool:{name}", field, evidence, f"Over-permissioned capability: {cap.label}"))
    return out


# --------------------------------------------------------------------------- #
# MCP005: weak input schema
# --------------------------------------------------------------------------- #

# Parameters that hand the model a way to run something: flagged per tool.
_RISKY_EXEC = frozenset({"command", "cmd", "script", "code", "sql", "shell", "executable", "program"})
# Parameters that name a target (file, URL, host). Nearly every file or HTTP tool has one and a
# JSON schema cannot express "inside the allowed directory", so these are low severity and
# reported once per manifest instead of once per tool.
_RISKY_TARGET = frozenset({
    "path", "filepath", "file", "filename", "dir", "directory", "folder", "root",
    "url", "uri", "endpoint", "host", "hostname", "args", "arguments", "expression",
})
_CONSTRAINTS = ("enum", "const", "pattern", "maxLength", "oneOf", "anyOf", "allOf")


def _iter_properties(schema: Dict[str, Any], prefix: str = "", depth: int = 0) -> Iterator[Tuple[str, str, Dict[str, Any]]]:
    if depth > 8:
        return
    props = schema.get("properties")
    if isinstance(props, dict):
        for key, spec in props.items():
            if not isinstance(spec, dict):
                continue
            path = f"{prefix}.{key}" if prefix else str(key)
            yield path, str(key), spec
            yield from _iter_properties(spec, path, depth + 1)
    items = schema.get("items")
    if isinstance(items, dict):
        yield from _iter_properties(items, f"{prefix}[]", depth + 1)


def _is_string(spec: Dict[str, Any]) -> bool:
    t = spec.get("type")
    return t == "string" or (isinstance(t, list) and "string" in t)


def _name_list(names: Iterable[str], limit: int = 3) -> str:
    ordered = sorted(set(names))
    shown = ", ".join(ordered[:limit])
    return shown + (f", +{len(ordered) - limit} more" if len(ordered) > limit else "")


def check_mcp005(tools: List[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    target_params: Dict[str, List[str]] = {}  # parameter path -> tools where it is unconstrained
    open_tools: List[str] = []
    for i, tool in enumerate(tools):
        name = tool_name(tool, i)
        subject = f"tool:{name}"
        schema = _input_schema(tool)
        if schema is None:
            out.append(_finding("MCP005", L, subject, "inputSchema", "no inputSchema declared", "Tool has no input schema"))
            continue
        for path, key, spec in _iter_properties(schema):
            if not _is_string(spec) or any(c in spec for c in _CONSTRAINTS):
                continue
            norm = _norm(key)
            last = norm.split("_")[-1] if norm else ""
            if last in _RISKY_EXEC or norm in _RISKY_EXEC:
                out.append(_finding(
                    "MCP005", M, subject, f"inputSchema.properties.{path}",
                    f"free-form string parameter '{path}' has no enum, pattern or maxLength",
                    "Unconstrained string for a risky parameter",
                ))
            elif last in _RISKY_TARGET or norm in _RISKY_TARGET:
                target_params.setdefault(path, []).append(name)
        props = schema.get("properties")
        if isinstance(props, dict) and props and schema.get("additionalProperties") is not False:
            open_tools.append(name)

    total = len(tools)
    for path in sorted(target_params):
        names = target_params[path]
        out.append(_finding(
            "MCP005", L, "manifest", f"inputSchema.properties.{path}",
            f"'{path}' is a free-form string (no enum, pattern or maxLength) in {len(set(names))} of {total} tools: {_name_list(names)}",
            "Unconstrained string for a risky parameter",
        ))
    if open_tools:
        out.append(_finding(
            "MCP005", L, "manifest", "inputSchema.additionalProperties",
            f"additionalProperties is not false in {len(set(open_tools))} of {total} tools: {_name_list(open_tools)}",
            "Input schemas allow additional properties",
        ))
    return out


# --------------------------------------------------------------------------- #
# MCP006: missing annotations on state-changing tools
# --------------------------------------------------------------------------- #

_WRITE_TOKENS = frozenset({
    "create", "write", "delete", "remove", "update", "set", "send", "post", "put", "patch",
    "insert", "drop", "exec", "execute", "run", "move", "rename", "kill", "deploy", "upload",
    "add", "edit", "modify", "commit", "push", "publish", "install", "uninstall", "truncate",
    "reset", "clear", "merge", "approve", "cancel", "revoke", "grant", "apply", "save",
    "append", "destroy", "terminate", "restart", "stop",
})
_READ_TOKENS = frozenset({"get", "list", "read", "search", "find", "fetch", "describe", "show", "view", "query", "lookup", "check", "count"})


def _looks_state_changing(name: str) -> bool:
    tokens = _norm(name).split("_")
    if not tokens or tokens[0] in _READ_TOKENS:
        return False
    return any(t in _WRITE_TOKENS for t in tokens)


def check_mcp006(tools: List[Dict[str, Any]]) -> List[Finding]:
    """One finding per manifest: servers usually lack annotations on all their write tools at once."""
    missing: List[str] = []
    for i, tool in enumerate(tools):
        name = tool_name(tool, i)
        if not _looks_state_changing(name):
            continue
        ann = tool.get("annotations")
        if isinstance(ann, dict) and ("readOnlyHint" in ann or "destructiveHint" in ann):
            continue
        missing.append(name)
    if not missing:
        return []
    return [_finding(
        "MCP006", L, "manifest", "annotations",
        f"{len(set(missing))} of {len(tools)} tools look state-changing but declare neither hint: {_name_list(missing)}",
        "State-changing tools lack readOnlyHint/destructiveHint",
    )]


# --------------------------------------------------------------------------- #
# MCP007: cross-tool references (shadowing)
# --------------------------------------------------------------------------- #

# "instead of / never use ... tool", not counting "this tool" (a description talking about itself).
_SHADOW_PHRASES = (
    _rx(r"\b(?:instead of|rather than|in place of|replaces?|overrides?|supersedes?|takes? precedence over|shadows?)\s+(?!this\b|the same\b)[^.\n]{0,40}\b(?:tools?|functions?)\b"),
    _rx(r"\b(?:do not|don't|never|stop)\s+(?:use|using|call|calling)\s+(?!this\b|the same\b|it\b)[^.\n]{0,40}\b(?:tools?|functions?)\b"),
)


def _is_distinctive(name: str) -> bool:
    """Names like read_file or getData are unlikely to appear in prose by accident."""
    return any(c in name for c in "_-.") or any(c.isdigit() for c in name) or (name != name.lower() and name != name.upper())


def _reference_pattern(name: str) -> "re.Pattern[str]":
    esc = re.escape(name)
    if _is_distinctive(name):
        return re.compile(rf"(?<![\w-]){esc}(?![\w-])")
    return re.compile(rf"[`'\"]{esc}[`'\"]|(?<![\w-]){esc}\(\)|(?<![\w-]){esc}(?= (?:tool|function)\b)|\b(?:tool|function) {esc}(?![\w-])")


_DEPRECATION = re.compile(r"\bdeprecat\w*", re.IGNORECASE)


def _sentence(text: str, start: int, end: int) -> str:
    """The sentence around a match: bounded by ., !, ? or a newline."""
    lo = max((text.rfind(c, 0, start) for c in ".!?\n"), default=-1) + 1
    hits = [i for i in (text.find(c, end) for c in ".!?\n") if i != -1]
    return text[lo : min(hits) if hits else len(text)]


def check_mcp007(tools: List[Dict[str, Any]]) -> List[Finding]:
    """References to sibling tools are routine workflow guidance ("then call X"), so they are
    reported once per manifest at LOW. Phrases that steer the model away from other tools stay
    MEDIUM per tool."""
    out: List[Finding] = []
    names = [tool_name(t, i) for i, t in enumerate(tools)]
    patterns = {n: _reference_pattern(n) for n in set(names)}
    refs: List[Tuple[str, str]] = []  # (tool, referenced tool)
    for i, tool in enumerate(tools):
        me = names[i]
        subject = f"tool:{me}"
        texts = [(f, t) for f, t in iter_text(tool, include_keys=False) if f != "name"]
        for other in sorted(patterns):
            if other != me and any(patterns[other].search(text) for _, text in texts):
                refs.append((me, other))
        for field, text in texts:
            hit = next((m for m in (rx.search(text) for rx in _SHADOW_PHRASES) if m), None)
            if hit:
                out.append(_finding("MCP007", M, subject, field, snippet(text, hit.start(), hit.end()), "Description steers the model away from or over other tools"))
                break
    if refs:
        examples = ", ".join(f"{a} \u2192 {b}" for a, b in sorted(refs)[:3]) + (f", +{len(refs) - 3} more" if len(refs) > 3 else "")
        out.append(_finding(
            "MCP007", L, "manifest", "description",
            f"{len(refs)} reference(s) to other tools across {len({a for a, _ in refs})} of {len(tools)} tools: {examples}",
            "Descriptions reference other tools",
        ))
    return out


# --------------------------------------------------------------------------- #
# MCP008: duplicate tool names
# --------------------------------------------------------------------------- #


def check_mcp008(tools: List[Dict[str, Any]]) -> List[Finding]:
    groups: Dict[str, List[str]] = {}
    for i, tool in enumerate(tools):
        name = tool.get("name")
        if isinstance(name, str) and name:
            groups.setdefault(_norm(name), []).append(name)
    out: List[Finding] = []
    for key in sorted(groups):
        names = groups[key]
        if len(names) < 2:
            continue
        exact = len(set(names)) == 1
        title = "Duplicate tool name" if exact else "Tool names differ only by case or separators"
        evidence = f"{len(names)} tools named '{names[0]}'" if exact else "names: " + ", ".join(f"'{n}'" for n in names)
        out.append(_finding("MCP008", M, f"tool:{names[0]}", "name", evidence, title))
    return out


MANIFEST_RULES: Tuple[Callable[[List[Dict[str, Any]]], List[Finding]], ...] = (
    check_mcp001, check_mcp002, check_mcp003, check_mcp004,
    check_mcp005, check_mcp006, check_mcp007, check_mcp008,
)


# --------------------------------------------------------------------------- #
# Config helpers
# --------------------------------------------------------------------------- #

_URL_KEYS = ("url", "serverUrl", "server_url", "endpoint", "baseUrl", "httpUrl")
_URL_IN_TEXT = re.compile(r"\b(?:https?|wss?)://[^\s'\"]+", re.IGNORECASE)
_SECRET_KEY = re.compile(
    r"secret|token|passw(?:or)?d|passwd|api[_-]?key|apikey|private[_-]?key|credential|auth|bearer|access[_-]?key",
    re.IGNORECASE,
)
_NON_SECRET_SUFFIX = re.compile(r"(?:_|-)?(?:file|path|url|uri|dir|name|type|mode|method|header|enabled|env|var|id)\Z", re.IGNORECASE)
_KNOWN_SECRET_VALUES = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bgithub_pat_\w{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[\w-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
    re.compile(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{5,}"),
    re.compile(r"\bglpat-[\w-]{20,}"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{30,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_REFERENCE = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{\{[^}]*\}\}|\$\(")
_PLACEHOLDER = re.compile(r"(?:x+|\*+|\.{3}|changeme|change_me|your[-_ ].*|<.*>|todo|placeholder|example|redacted|none|null|true|false|\d+)\Z", re.IGNORECASE)
_ARG_ASSIGN = re.compile(r"-{0,2}([\w-]+)=(.*)\Z", re.DOTALL)
_ARG_FLAG = re.compile(r"--?([\w-]+)\Z")


def _servers(servers: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    for name in sorted(servers):
        cfg = servers[name]
        if isinstance(cfg, dict):
            yield str(name), cfg


def _args(cfg: Dict[str, Any]) -> List[str]:
    args = cfg.get("args")
    return [a for a in args if isinstance(a, str)] if isinstance(args, list) else []


def _str_map(cfg: Dict[str, Any], key: str) -> Dict[str, str]:
    value = cfg.get(key)
    if not isinstance(value, dict):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, str)}


def _command_base(cfg: Dict[str, Any]) -> str:
    command = _str(cfg.get("command")).strip()
    base = re.split(r"[\\/]", command)[-1].lower()
    return re.sub(r"\.(?:exe|cmd|bat)\Z", "", base)


def _mask(value: str) -> str:
    return "***" if len(value) <= 8 else f"{value[:3]}*** ({len(value)} chars)"


def _redact(text: str) -> str:
    """Best-effort removal of secrets from text that will be shown as evidence."""
    for rx in _KNOWN_SECRET_VALUES:
        text = rx.sub("***", text)
    text = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", r"\1 ***", text)
    return re.sub(r"(?i)((?:token|secret|password|passwd|api[_-]?key)\w*=)\S+", r"\1***", text)


def _redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return "<unparseable url>"
    netloc = host
    if ":" in host:
        netloc = f"[{host}]"
    if parts.port:
        netloc += f":{parts.port}"
    if parts.username or parts.password:
        netloc = "***@" + netloc
    return f"{parts.scheme}://{netloc}{parts.path}" + ("?<redacted>" if parts.query else "")


_REMOTE_BRIDGE = re.compile(r"mcp-remote|mcp-proxy|mcp_proxy|supergateway|mcp-client|\bsse\b", re.IGNORECASE)


def _cfg_urls(cfg: Dict[str, Any], any_arg: bool = False) -> List[Tuple[str, str]]:
    """URLs a server config points at.

    URLs in args only count as MCP endpoints when the command looks like a
    remote bridge (mcp-remote, supergateway, ...); otherwise they are usually
    unrelated (a curl target, a docs link). ``any_arg`` includes them anyway.
    """
    found: List[Tuple[str, str]] = []
    for key in _URL_KEYS:
        value = cfg.get(key)
        if isinstance(value, str) and value.strip():
            found.append((key, value.strip()))
    args = _args(cfg)
    if any_arg or (_command_base(cfg) not in _SHELLS and _REMOTE_BRIDGE.search(" ".join(args))):
        for i, arg in enumerate(args):
            for m in _URL_IN_TEXT.finditer(arg):
                found.append((f"args[{i}]", m.group(0)))
    return found


def _is_local_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_unspecified


def _url_host(url: str) -> Optional[str]:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _is_reference_or_placeholder(value: str) -> bool:
    v = value.strip()
    return not v or bool(_REFERENCE.search(v)) or bool(_PLACEHOLDER.match(v))


def _known_secret(value: str) -> bool:
    return any(rx.search(value) for rx in _KNOWN_SECRET_VALUES)


# --------------------------------------------------------------------------- #
# CFG001: hardcoded secrets
# --------------------------------------------------------------------------- #


def _secret_key_like(key: str) -> bool:
    return bool(_SECRET_KEY.search(key)) and not _NON_SECRET_SUFFIX.search(key)


def check_cfg001(servers: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for name, cfg in _servers(servers):
        subject = f"server:{name}"
        candidates: List[Tuple[str, str, str]] = []  # (field, key, value)
        for section in ("env", "headers"):
            for key, value in sorted(_str_map(cfg, section).items()):
                candidates.append((f"{section}.{key}", key, value))
        args = _args(cfg)
        consumed = set()  # positions already paired with a preceding --flag
        for i, arg in enumerate(args):
            if i in consumed:
                continue
            m = _ARG_ASSIGN.match(arg)
            if m:
                candidates.append((f"args[{i}]", m.group(1), m.group(2)))
                continue
            flag = _ARG_FLAG.match(arg)
            if flag and i + 1 < len(args) and not args[i + 1].startswith("-") and not _ARG_ASSIGN.match(args[i + 1]):
                candidates.append((f"args[{i + 1}]", flag.group(1), args[i + 1]))
                consumed.add(i + 1)
            elif not arg.startswith("-"):
                candidates.append((f"args[{i}]", "", arg))
        for field, key, value in candidates:
            if _is_reference_or_placeholder(value):
                continue
            keyed = bool(key) and _secret_key_like(key) and len(value.strip()) >= 6
            if keyed or _known_secret(value):
                label = key or "value"
                out.append(_finding("CFG001", H, subject, field, f"{label} = {_mask(value.strip())}", f"Hardcoded secret in {field.split('.')[0].split('[')[0]}"))
        for field, url in _cfg_urls(cfg, any_arg=True):
            try:
                parts = urlsplit(url)
                userinfo = parts.password
                query = parse_qsl(parts.query)
            except ValueError:
                continue
            if userinfo and not _is_reference_or_placeholder(userinfo):
                out.append(_finding("CFG001", H, subject, field, f"credentials embedded in URL: {_redact_url(url)}", "Hardcoded secret in url"))
            for qk, qv in query:
                if _secret_key_like(qk) and not _is_reference_or_placeholder(qv) and len(qv) >= 6:
                    out.append(_finding("CFG001", H, subject, field, f"query parameter {qk} = {_mask(qv)}", "Hardcoded secret in url"))
    return _dedupe(out)


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.subject, f.field, f.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# --------------------------------------------------------------------------- #
# CFG002: plaintext HTTP
# --------------------------------------------------------------------------- #


def check_cfg002(servers: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for name, cfg in _servers(servers):
        for field, url in _cfg_urls(cfg):
            scheme = url.split(":", 1)[0].lower()
            host = _url_host(url)
            if scheme in ("http", "ws") and host and not _is_local_host(host):
                out.append(_finding("CFG002", H, f"server:{name}", field, _redact_url(url)))
    return out


# --------------------------------------------------------------------------- #
# CFG003: remote server without visible auth
# --------------------------------------------------------------------------- #

_AUTH_CONFIG_KEYS = ("auth", "oauth", "authorization", "authProvider", "bearer_token_env_var", "bearerTokenEnvVar")


def _has_visible_auth(cfg: Dict[str, Any], urls: List[Tuple[str, str]]) -> bool:
    if any(k in cfg for k in _AUTH_CONFIG_KEYS):
        return True
    if any(_secret_key_like(k) or "key" in k.lower() for k in _str_map(cfg, "headers")):
        return True
    if any(_secret_key_like(k) for k in _str_map(cfg, "env")):
        return True
    for _, url in urls:
        try:
            parts = urlsplit(url)
            if parts.username or parts.password or any(_secret_key_like(k) or k.lower() in ("key", "apikey") for k, _ in parse_qsl(parts.query)):
                return True
        except ValueError:
            continue
    return any(re.search(r"authorization|bearer|api[-_]?key|--token", a, re.IGNORECASE) for a in _args(cfg))


def check_cfg003(servers: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for name, cfg in _servers(servers):
        urls = [(f, u) for f, u in _cfg_urls(cfg) if _url_host(u) and not _is_local_host(_url_host(u) or "")]
        if not urls or _has_visible_auth(cfg, urls):
            continue
        field, url = urls[0]
        out.append(_finding("CFG003", M, f"server:{name}", field, f"{_redact_url(url)}: no auth header, credential or oauth setting found"))
    return out


# --------------------------------------------------------------------------- #
# CFG004: unpinned launcher packages
# --------------------------------------------------------------------------- #

_NPM_LAUNCHERS = {"npx", "bunx"}
_PY_LAUNCHERS = {"uvx", "pipx"}
# Flags (per launcher) whose value is a package spec, and flags whose value must be skipped.
_SPEC_FLAGS = {"npx": {"-p", "--package"}, "bunx": {"-p", "--package"}, "uvx": {"--from"}, "pipx": {"--spec"}}
_VALUE_FLAGS = {
    "npx": {"-c", "--call", "--registry", "--cache", "--userconfig"},
    "bunx": {"--registry", "--cwd"},
    "uvx": {"--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--with-requirements", "--env-file", "--directory", "--project", "--config-file", "--with-editable", "-c", "--constraints"},
    "pipx": {"--python", "--pip-args", "--index-url"},
}
_EXACT_VERSION = re.compile(r"=?v?\d+\.\d+\.\d+(?:[-+][\w.+-]+)?\Z")
_GIT_REF = re.compile(r"(?:v?\d+\.\d+\.\d+.*|[0-9a-f]{7,40})\Z")


def _launcher_and_args(cfg: Dict[str, Any]) -> Optional[Tuple[str, List[str]]]:
    base = _command_base(cfg)
    args = _args(cfg)
    if base in _NPM_LAUNCHERS or base in _PY_LAUNCHERS:
        return base, args
    if base in ("pnpm", "yarn") and args and args[0] == "dlx":
        return "npx", args[1:]
    if base == "npm" and args and args[0] in ("exec", "x"):
        return "npx", args[1:]
    if base == "bun" and args and args[0] == "x":
        return "bunx", args[1:]
    return None


def _package_spec(launcher: str, args: List[str]) -> Optional[str]:
    spec_flags = _SPEC_FLAGS[launcher]
    value_flags = _VALUE_FLAGS[launcher]
    i = 0
    if launcher == "pipx" and args and args[0] == "run":
        i = 1
    while i < len(args):
        arg = args[i]
        if arg in spec_flags:
            return args[i + 1] if i + 1 < len(args) else None
        if "=" in arg and arg.split("=", 1)[0] in spec_flags:
            return arg.split("=", 1)[1]
        if arg in value_flags:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return arg
    return None


def _is_pinned(launcher: str, spec: str) -> Optional[bool]:
    """True/False for pinned/unpinned; None when the spec is a local path (not applicable)."""
    if spec.startswith((".", "/", "~", "file:")) or spec.endswith((".whl", ".tar.gz", ".tgz")):
        return None
    if "://" in spec or spec.startswith(("git+", "github:", "gitlab:")):
        ref = re.split(r"[#@]", spec.split("://", 1)[-1])[-1] if re.search(r"[#@]", spec.split("://", 1)[-1]) else ""
        return bool(_GIT_REF.match(ref))
    if launcher in _NPM_LAUNCHERS:
        at = spec.find("@", 1)
        return at != -1 and bool(_EXACT_VERSION.match(spec[at + 1:]))
    # Python: pkg==1.2.3 (no wildcard) or uvx-style pkg@1.2.3
    if re.search(r"==\s*[\w.!+-]+\Z", spec) and not spec.endswith(".*"):
        return True
    at = spec.rfind("@")
    return at > 0 and bool(_EXACT_VERSION.match(spec[at + 1:]))


def check_cfg004(servers: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for name, cfg in _servers(servers):
        parsed = _launcher_and_args(cfg)
        if not parsed:
            continue
        launcher, args = parsed
        spec = _package_spec(launcher if launcher in _SPEC_FLAGS else "npx", args)
        if not spec:
            continue
        if _is_pinned(launcher, spec) is False:
            out.append(_finding("CFG004", M, f"server:{name}", "args", f"{_command_base(cfg)} {spec}"))
    return out


# --------------------------------------------------------------------------- #
# CFG005: launched via shell or curl|sh
# --------------------------------------------------------------------------- #

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "cmd", "powershell", "pwsh"})
_CURL_PIPE = re.compile(
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*(?:iex|invoke-expression)\b|\b(?:ba|z)?sh\b[^\n]*<\(\s*(?:curl|wget)",
    re.IGNORECASE,
)
_SHELL_META = re.compile(r"[;&|`<>]|\$\(|\beval\b|\b(?:curl|wget)\b", re.IGNORECASE)


def check_cfg005(servers: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for name, cfg in _servers(servers):
        subject = f"server:{name}"
        command = _str(cfg.get("command"))
        args = _args(cfg)
        full = " ".join([command] + args)
        base = _command_base(cfg)
        if _CURL_PIPE.search(full):
            out.append(_finding("CFG005", H, subject, "command", _redact(full), "Server launched by piping a download into a shell"))
        elif base in _SHELLS:
            severity = H if _SHELL_META.search(" ".join(args)) else M
            out.append(_finding("CFG005", severity, subject, "command", _redact(full), "Server launched through a shell"))
        elif _SHELL_META.search(command):
            out.append(_finding("CFG005", H, subject, "command", _redact(full), "Server command contains shell operators"))
    return out


# --------------------------------------------------------------------------- #
# CFG006: overly broad filesystem root
# --------------------------------------------------------------------------- #

_BROAD_PATHS = frozenset({"/", "~", "~/", "$HOME", "${HOME}", "$HOME/", "${HOME}/", "%USERPROFILE%", "%HOMEPATH%", "/Users", "/Users/", "/home", "/home/"})
_BROAD_PATH_PATTERNS = (
    re.compile(r"/(?:Users|home)/[^/\\]+/?\Z"),
    re.compile(r"[A-Za-z]:[\\/]?\Z"),
    re.compile(r"[A-Za-z]:[\\/]Users[\\/][^\\/]+[\\/]?\Z", re.IGNORECASE),
)


def _is_broad_path(value: str) -> bool:
    v = value.strip().strip("'\"")
    return v in _BROAD_PATHS or any(p.match(v) for p in _BROAD_PATH_PATTERNS)


def _path_candidates(arg: str) -> List[str]:
    cands = [arg]
    if arg.startswith("-") and "=" in arg:
        cands.append(arg.split("=", 1)[1])
    for m in re.finditer(r"(?:source|src)=([^,]+)", arg):
        cands.append(m.group(1))
    for c in list(cands):
        if ":" in c and c.startswith(("/", "~", "$")):  # docker -v /:/host
            cands.append(c.split(":", 1)[0])
    return cands


def check_cfg006(servers: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for name, cfg in _servers(servers):
        for i, arg in enumerate(_args(cfg)):
            hit = next((c for c in _path_candidates(arg) if _is_broad_path(c)), None)
            if hit is not None:
                out.append(_finding("CFG006", H, f"server:{name}", f"args[{i}]", f"argument: {hit.strip()}"))
    return out


CONFIG_RULES: Tuple[Callable[[Dict[str, Any]], List[Finding]], ...] = (
    check_cfg001, check_cfg002, check_cfg003, check_cfg004, check_cfg005, check_cfg006,
)

# mcpscan

Open-source static security scanner for MCP (Model Context Protocol) servers.
Goal: a developer-first "linter for MCP servers" that runs locally and in CI.

## Principles
- Zero runtime dependencies (stdlib only). Python >= 3.9.
- Every finding must be explainable: rule ID, severity, evidence snippet, remediation.
- Prefer few false positives over exhaustive coverage. When unsure, lower severity.
- Static analysis only in v0.1. Never execute or connect to the servers being scanned.
- Deterministic output (sorted findings) so results are diffable in CI.
- Scanned files are untrusted: evidence is escaped (no terminal escapes) and secrets are masked in every report.

## Layout
src/mcpscan/
  models.py    Severity enum, Finding, ScanResult dataclasses; output sanitising
  rules.py     One function per rule; pure functions, no I/O; RULE_INFO metadata
  scanner.py   Detects input type (tool manifest vs client config) and runs rules
  report.py    Renderers: terminal (color optional), JSON, Markdown, SARIF
  suppress.py  Baseline (--baseline/--write-baseline) and ignore-file (--ignore-file) handling
  cli.py       argparse entrypoint: `mcpscan scan <path>`
action.yml    GitHub Action (composite); scripts/run-scan.sh is its scan step
tests/         pytest; one test per rule (a positive and a negative case)
examples/      vulnerable_manifest.json, safe_manifest.json, vulnerable_config.json

## Inputs supported
1. Tool manifest: JSON from an MCP `tools/list` response ({"tools": [...]}, a bare list, or a JSON-RPC response with result.tools).
2. Client config: `claude_desktop_config.json` / `mcp.json` style ({"mcpServers": {...}}; also {"servers": ...} and {"mcp": {"servers": ...}}).

## Rules
Manifest rules:
- MCP001 Tool poisoning / prompt injection in name, description, or schema text
  (instruction override, hidden <IMPORTANT> tags, concealment from user,
  forced tool calls, exfiltration directives). CRITICAL/HIGH.
- MCP002 Invisible Unicode (categories Cf/Co/Cn/Cs, excluding ZWJ) in metadata. HIGH.
- MCP003 References to sensitive files (~/.ssh, .env, .aws/credentials...). HIGH.
- MCP004 Over-permissioned capability (command exec, fs write/delete, raw SQL,
  arbitrary URL fetch, secret access, outbound messaging). MEDIUM/HIGH.
- MCP005 Weak input schema: free-form string for risky param names (path, command,
  url, query...) without enum/pattern/maxLength; missing schema; additionalProperties not false.
- MCP006 State-changing tool lacks readOnlyHint/destructiveHint annotations. LOW.
- MCP007 Description references another tool (cross-tool shadowing). MEDIUM.
- MCP008 Duplicate tool names. MEDIUM.
Config rules:
- CFG001 Hardcoded secret in env/headers/args/URL. HIGH.
- CFG002 Remote server over plaintext HTTP (non-localhost). HIGH.
- CFG003 Remote server with no visible auth. MEDIUM.
- CFG004 Unpinned npx/uvx/pipx package. MEDIUM.
- CFG005 Launched via shell or curl|sh. HIGH (plain shell wrapper: MEDIUM).
- CFG006 Overly broad filesystem root (/, ~, home dir). HIGH.

## CLI contract
mcpscan scan <path> [--format text|json|markdown|sarif] [--fail-on low|medium|high|critical] [--output FILE]
                     [--baseline FILE | --write-baseline FILE] [--ignore-file FILE]
Exit codes: 0 = clean (or below threshold), 1 = findings at/above --fail-on (default: low), 2 = usage/parse error.
Suppressed findings (baseline/ignore) never affect the exit code but are always counted in reports. Ignore entries require a `reason`.

## Commands
- Install dev: pip install -e ".[dev]"
- Test: pytest -q
- Run: mcpscan scan examples/vulnerable_manifest.json

## Definition of done for any change
- Tests pass, new rule has positive + negative tests.
- README rule table updated (and the rule added to RULE_INFO).
- No new dependencies without discussion.
- Must still parse on Python 3.9 (no `match`, no `X | Y` at runtime, no `slots=True`).

## Roadmap (do not build until asked)
Live stdio/HTTP introspection, rug-pull detection (hash tool metadata across runs),
server-source scanning.

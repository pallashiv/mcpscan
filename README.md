# mcpscan

A static security scanner for [MCP](https://modelcontextprotocol.io) (Model Context Protocol) servers: a linter for tool manifests and client configs that runs locally and in CI.

- **Static only.** mcpscan reads a JSON file. It never starts, connects to, or executes the servers it scans.
- **Zero runtime dependencies.** Standard library only, Python 3.9+.
- **Explainable.** Every finding has a rule ID, severity, evidence snippet and remediation.
- **Low noise.** When a rule is unsure it reports a lower severity rather than a false alarm.
- **Deterministic.** Findings are sorted, so reports diff cleanly in CI.

## Install

```sh
pip install -e ".[dev]"   # development
```

## Usage

```sh
mcpscan scan <path> [--format text|json|markdown|sarif] [--fail-on low|medium|high|critical] [--output FILE]
```

```sh
mcpscan scan examples/vulnerable_manifest.json
mcpscan scan claude_desktop_config.json --fail-on high
mcpscan scan tools.json --format sarif --output mcpscan.sarif
```

| Exit code | Meaning |
| --- | --- |
| 0 | Clean, or all findings are below `--fail-on` |
| 1 | At least one finding at or above `--fail-on` (default `low`, i.e. any finding) |
| 2 | Usage error, unreadable file, invalid JSON or unrecognised input |

Text output is colored on a terminal; set `NO_COLOR` to disable. Text from scanned files is escaped in every format, so a hostile manifest cannot inject terminal escape sequences, and values that look like secrets are masked in evidence.

### Supported inputs

1. **Tool manifest**: the JSON from an MCP `tools/list` response, as `{"tools": [...]}`, a bare list, or a raw JSON-RPC response with `result.tools`.
2. **Client config**: `claude_desktop_config.json` / `mcp.json` style `{"mcpServers": {...}}` (also `{"servers": {...}}` as used by VS Code, including under `"mcp"`). A config with no servers (for example a Claude Desktop config that only has `preferences`) scans clean with a note, exit 0. Files that are neither a manifest nor a config exit 2.

## Rules

| ID | Severity | What it detects |
| --- | --- | --- |
| MCP001 | CRITICAL / HIGH | Tool poisoning or prompt injection in name, description or schema text: hidden `<IMPORTANT>` tags, concealment from the user, exfiltration directives (critical); instruction override, forced tool calls (high) |
| MCP002 | HIGH | Invisible Unicode (categories Cf, Co, Cn and lone surrogates, excluding ZWJ) in metadata |
| MCP003 | HIGH | References to sensitive files: `~/.ssh`, `.env`, `.aws/credentials`, `/etc/passwd`, `.npmrc`, ... |
| MCP004 | HIGH / MEDIUM | Over-permissioned capability: command execution, raw SQL, secret access (high); filesystem write/delete, arbitrary URL fetch, outbound messaging (medium). Wording like "any file" escalates to high; a matching parameter name alone lowers severity one level |
| MCP005 | MEDIUM / LOW | Weak input schema: free-form string for a risky parameter such as `path`, `command`, `url` without `enum`/`pattern`/`maxLength` (medium; `query`, `args` low); missing schema or `additionalProperties` not `false` (low) |
| MCP006 | LOW | State-changing tool has neither `readOnlyHint` nor `destructiveHint` |
| MCP007 | MEDIUM | Description references another tool (cross-tool shadowing), or steers the model away from other tools |
| MCP008 | MEDIUM | Duplicate tool names, including names that differ only by case or `-`/`_` |
| CFG001 | HIGH | Hardcoded secret in `env`, `headers`, args or a URL (secret-like key names and known token formats) |
| CFG002 | HIGH | Remote server over plaintext `http://` / `ws://` on a non-local host |
| CFG003 | MEDIUM | Remote server with no visible auth. Ignore if the client handles OAuth for it |
| CFG004 | MEDIUM | Unpinned `npx` / `uvx` / `pipx` (also `pnpm dlx`, `bunx`) package |
| CFG005 | HIGH / MEDIUM | Launched through a shell or `curl \| sh` (high); a plain shell wrapper such as `cmd /c npx ...` is medium |
| CFG006 | HIGH | Filesystem root of `/`, `~`, `$HOME`, a whole home directory or a drive root |

## Layout

```
src/mcpscan/
  models.py    Severity, Finding, ScanResult; output sanitising
  rules.py     One pure function per rule; rule metadata (RULE_INFO)
  scanner.py   Detects input type and runs the rules
  report.py    Renderers: text, JSON, Markdown, SARIF 2.1.0
  cli.py       argparse entrypoint
tests/         pytest; a positive and a negative test per rule
examples/      vulnerable_manifest.json, safe_manifest.json, vulnerable_config.json
```

## Development

```sh
pip install -e ".[dev]"
pytest -q
```

A new rule needs a positive and a negative test, a row in the table above, and an entry in `RULE_INFO`.

## Not yet built

Live stdio/HTTP introspection, rug-pull detection (hashing tool metadata across runs), a GitHub Action, a baseline/ignore file, and server-source scanning.

## License

[MIT](LICENSE)

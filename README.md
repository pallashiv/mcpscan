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
                     [--baseline FILE | --write-baseline FILE] [--ignore-file FILE]
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

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only needed for upload-sarif

jobs:
  mcpscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: pallashiv/mcpscan@main
        with:
          path: claude_desktop_config.json
          fail-on: high
          upload-sarif: true
```

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | required | Manifest or config JSON file, relative to the workspace |
| `fail-on` | `low` | Fail the job at or above this severity |
| `baseline` | | Baseline file; only findings not in it can fail the job |
| `ignore-file` | | JSON ignore file (rule ID plus a required reason per entry) |
| `sarif-file` | `mcpscan.sarif` | Where to write the SARIF report |
| `upload-sarif` | `false` | Upload the SARIF to code scanning (results appear in the Security tab) |
| `python-version` | `3.12` | Python used to run mcpscan |

The action prints the text report in the job log, uploads SARIF (if enabled) before failing the job, and sets an `exit-code` output (0, 1 or 2, as for the CLI). To scan several files, add one step per file with a different `sarif-file`; give each upload a distinct file so results do not overwrite each other. The action installs mcpscan from the ref you pin, so pin a tag or commit SHA once releases exist.

### Adopting mcpscan on an existing project

Save today's findings as a baseline, commit it, and gate CI on new findings only:

```sh
mcpscan scan tools.json --write-baseline mcpscan-baseline.json   # writes the file, exits 0
mcpscan scan tools.json --baseline mcpscan-baseline.json          # exits 1 only for findings not in the baseline
```

- Findings match on rule, subject, field and title, not on the evidence text, so editing a description does not resurface an accepted finding.
- Suppressed findings are never dropped silently: the summary shows a count, and JSON and SARIF output list them (SARIF marks them as suppressed).
- If fixed findings leave stale entries in the baseline, the summary says so; regenerate with `--write-baseline`.
- Use one baseline per scanned file: subjects such as `server:github` can repeat across files.

To accept a specific finding with a recorded reason, use an ignore file:

```json
{
  "ignore": [
    {"rule": "MCP004", "subject": "tool:run_shell_command", "reason": "Shell access is this tool's purpose; reviewed in TICKET-123"},
    {"rule": "MCP005", "subject": "manifest", "field": "inputSchema.properties.path", "reason": "Server restricts paths to its allowed directories"}
  ]
}
```

`subject` and `field` are optional globs (default `*`). `reason` is required, and unknown rule IDs or keys are rejected so typos cannot silently disable a check. Ignore rules take precedence over the baseline.

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
| MCP005 | MEDIUM / LOW | Weak input schema: free-form string for an exec-like parameter such as `command`, `sql`, `script` (medium, per tool); for `path`, `url`, `host` and similar (low, once per manifest, since almost every file or HTTP tool has one); missing schema (low); `additionalProperties` not `false` (low, once per manifest) |
| MCP006 | LOW | State-changing tool has neither `readOnlyHint` nor `destructiveHint` |
| MCP007 | MEDIUM / LOW | Description references another tool (cross-tool shadowing), or steers the model away from other tools. A "DEPRECATED: use X instead" notice is low |
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
  suppress.py  Baseline and ignore files
  cli.py       argparse entrypoint
action.yml     GitHub Action (composite); scripts/run-scan.sh is its scan step
tests/         pytest; a positive and a negative test per rule; fixtures/real/ holds real server manifests
examples/      vulnerable_manifest.json, safe_manifest.json, vulnerable_config.json
```

## Development

```sh
pip install -e ".[dev]"
pytest -q
```

A new rule needs a positive and a negative test, a row in the table above, and an entry in `RULE_INFO`.

## Not yet built

Live stdio/HTTP introspection, rug-pull detection (hashing tool metadata across runs), and server-source scanning.

## License

[MIT](LICENSE)

Real `tools/list` output captured on 2026-09-21 with the MCP Inspector CLI, used to guard against
false positives (see `tests/test_real_manifests.py`). Each file is a tool list only; no server
code and no secrets. The text belongs to the respective projects and is used here as test data
under their open-source licences.

| File | Server |
| --- | --- |
| everything, filesystem, memory, thinking | `@modelcontextprotocol/server-everything`, `-filesystem`, `-memory`, `-sequential-thinking` (MIT/Apache-2.0: the MCP project is transitioning between them, see its LICENSE) |
| github | `@modelcontextprotocol/server-github` (MIT) |
| context7 | `@upstash/context7-mcp` (MIT) |
| playwright | `@playwright/mcp` (Apache-2.0) |
| desktop-commander | `@wonderwhy-er/desktop-commander` (MIT) |

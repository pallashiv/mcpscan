# Security

## Reporting a vulnerability

Please report security issues privately, not in a public issue. Use GitHub's private vulnerability
reporting on this repository (Security tab, then "Report a vulnerability"). Include the mcpscan
version (`mcpscan --version`), the input that triggers the problem (remove real secrets), and what
you expected to happen.

Only the latest release is supported.

## What mcpscan does and does not do

mcpscan is a local command-line tool. It reads one JSON file that you point it at and prints a
report. It never asks for, receives or uploads anything on its own.

| | |
| --- | --- |
| **Reads** | The file you name: a tool manifest (a `tools/list` response: tool names, descriptions and argument schemas) or a client config (which servers you use). It does not read databases, application data or anything else. |
| **Network** | None. The code imports no networking modules. |
| **Runs other programs** | Never. No subprocesses, no `eval`/`exec`. It does not start, connect to or execute the servers it scans. |
| **Dependencies** | None at runtime (Python standard library only), which keeps the code small enough to review. |
| **Writes** | Only files you name: `--output` and `--write-baseline`. |
| **Secrets** | Values that look like secrets are masked in every report format. Text from scanned files is escaped, so a hostile file cannot inject terminal escape sequences. |

These properties are enforced by a test (`tests/test_no_network.py`) that fails if the code starts
importing networking or process modules, calling `eval`/`exec`, or gaining a runtime dependency.

## Limits

- Detection is heuristic. The injection rules match known phrasing, so a determined attacker can
  word things to avoid them. A clean scan is not proof that a server is safe, and a finding is not
  proof that it is malicious.
- mcpscan has not had an independent security audit. It is early software from a single maintainer.
- mcpscan analyses what a server declares, not what its code does.

## Using the GitHub Action safely

- **Pin a commit SHA**, not a tag or `@main`. The Action installs mcpscan from the ref you pin, so
  a moving ref means running whatever is there on the day.
- **Give it the least permission.** `contents: read` is enough. Add `security-events: write` only
  if you turn on `upload-sarif`.
- **`upload-sarif` sends findings to your repository's code scanning** through GitHub: tool names,
  line numbers and short evidence snippets taken from descriptions. Nothing goes to the mcpscan
  author. If descriptions in your files are sensitive, leave it off and read the job log instead.

## Capturing tool lists: running third-party servers is not free

mcpscan scans files, but to get a server's tool list you usually have to run the server, and that
executes third-party code with your permissions. Servers can do more than answer `tools/list`. In
testing, one popular server opened a welcome page in the browser, wrote a config file with
telemetry enabled, and downloaded a roughly 500 MB browser as a dependency.

If you capture manifests yourself:

- Do it in a container, VM or other disposable environment, not on a machine that holds credentials.
- Do not give the process real API tokens; a placeholder is enough for `tools/list`.
- Prefer sources that need no execution: a server's documentation, its source, or a manifest the
  vendor publishes.
- Afterwards, check what the server left behind (config directories, caches, running processes).

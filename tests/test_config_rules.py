"""One positive and one negative test per config rule."""

from mcpscan.models import Severity
from mcpscan.rules import (
    check_cfg001, check_cfg002, check_cfg003, check_cfg004, check_cfg005, check_cfg006,
)


def one(cfg, name="srv"):
    return {name: cfg}


def ids(findings):
    return [f.rule_id for f in findings]


# CFG001 ---------------------------------------------------------------------

def test_cfg001_secret_in_env_is_masked_in_evidence():
    findings = check_cfg001(one({"command": "x", "env": {"API_KEY": "supersecretvalue123"}}))
    assert ids(findings) == ["CFG001"] and findings[0].severity == Severity.HIGH
    assert "supersecretvalue123" not in findings[0].evidence


def test_cfg001_known_token_format_and_header_and_url_credentials():
    assert check_cfg001(one({"env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}}))
    assert check_cfg001(one({"headers": {"Authorization": "Bearer abcdef123456"}}))
    assert check_cfg001(one({"url": "https://user:hunter2hunter2@example.com/mcp"}))
    assert check_cfg001(one({"url": "https://example.com/mcp?api_key=abcdef123456"}))


def test_cfg001_secret_passed_as_argument():
    assert check_cfg001(one({"command": "x", "args": ["--token=abcdef123456"]}))
    assert check_cfg001(one({"command": "x", "args": ["--api-key", "abcdef123456"]}))
    assert check_cfg001(one({"command": "docker", "args": ["run", "-e", "GITHUB_TOKEN=abcdef123456"]}))


def test_cfg001_negative_references_placeholders_and_non_secrets():
    cfg = {
        "env": {"API_KEY": "${API_KEY}", "TOKEN": "$TOKEN", "PASSWORD": "<your-password>",
                "AUTH_ENABLED": "true", "TOKEN_FILE": "/run/secrets/token", "LOG_LEVEL": "debug"},
        "headers": {"Authorization": "Bearer ${MCP_TOKEN}", "Content-Type": "application/json"},
    }
    assert check_cfg001(one(cfg)) == []


# CFG002 ---------------------------------------------------------------------

def test_cfg002_plaintext_remote_flagged_and_credentials_redacted():
    findings = check_cfg002(one({"url": "http://user:pw@mcp.example.com/sse?token=abc"}))
    assert ids(findings) == ["CFG002"]
    assert "pw" not in findings[0].evidence.replace("mcp.example", "") and "abc" not in findings[0].evidence


def test_cfg002_negative_https_and_local():
    for url in ("https://mcp.example.com", "http://localhost:3000/mcp", "http://127.0.0.1:8080", "http://[::1]:9000", "http://app.localhost/x"):
        assert check_cfg002(one({"url": url})) == [], url


def test_cfg002_mcp_remote_bridge_url_in_args():
    cfg = {"command": "npx", "args": ["mcp-remote", "http://mcp.example.com/sse"]}
    assert ids(check_cfg002(one(cfg))) == ["CFG002"]


# CFG003 ---------------------------------------------------------------------

def test_cfg003_remote_without_auth_flagged():
    findings = check_cfg003(one({"url": "https://mcp.example.com/mcp"}))
    assert ids(findings) == ["CFG003"] and findings[0].severity == Severity.MEDIUM


def test_cfg003_negative_with_auth_or_local():
    assert check_cfg003(one({"url": "https://x.example.com", "headers": {"Authorization": "Bearer ${T}"}})) == []
    assert check_cfg003(one({"url": "https://x.example.com", "headers": {"X-API-Key": "${K}"}})) == []
    assert check_cfg003(one({"url": "https://x.example.com", "oauth": {"clientId": "abc"}})) == []
    assert check_cfg003(one({"url": "http://localhost:3000"})) == []
    assert check_cfg003(one({"command": "node", "args": ["server.js"]})) == []


def test_cfg003_ignores_unrelated_urls_in_shell_args():
    cfg = {"command": "bash", "args": ["-c", "curl https://example.com/install.sh"]}
    assert check_cfg003(one(cfg)) == []


# CFG004 ---------------------------------------------------------------------

def test_cfg004_unpinned_launchers_flagged():
    cases = [
        {"command": "npx", "args": ["-y", "@scope/server"]},
        {"command": "npx", "args": ["-y", "server@latest"]},
        {"command": "npx", "args": ["server@^1.2.0"]},
        {"command": "uvx", "args": ["mcp-server-fetch"]},
        {"command": "uvx", "args": ["--from", "pkg>=1.0", "cmd"]},
        {"command": "pipx", "args": ["run", "pkg"]},
        {"command": "pnpm", "args": ["dlx", "server"]},
    ]
    for cfg in cases:
        assert ids(check_cfg004(one(cfg))) == ["CFG004"], cfg


def test_cfg004_negative_pinned_or_not_a_launcher():
    cases = [
        {"command": "npx", "args": ["-y", "@scope/server@1.2.3"]},
        {"command": "npx", "args": ["server@2.0.0-beta.1"]},
        {"command": "uvx", "args": ["mcp-server-fetch==1.0.2"]},
        {"command": "uvx", "args": ["--python", "3.12", "mcp-server-fetch@1.0.2"]},
        {"command": "pipx", "args": ["run", "--spec", "pkg==2.0.0", "cmd"]},
        {"command": "node", "args": ["server.js"]},
        {"command": "npx", "args": ["./local-server"]},
    ]
    for cfg in cases:
        assert check_cfg004(one(cfg)) == [], cfg


# CFG005 ---------------------------------------------------------------------

def test_cfg005_curl_pipe_sh_is_high():
    cfg = {"command": "bash", "args": ["-c", "curl -fsSL https://x.example/i.sh | sh"]}
    findings = check_cfg005(one(cfg))
    assert ids(findings) == ["CFG005"] and findings[0].severity == Severity.HIGH


def test_cfg005_shell_with_compound_command_high_plain_wrapper_medium():
    compound = check_cfg005(one({"command": "sh", "args": ["-c", "cd /app && ./run"]}))
    wrapper = check_cfg005(one({"command": "cmd", "args": ["/c", "npx", "-y", "pkg@1.0.0"]}))
    assert compound[0].severity == Severity.HIGH and wrapper[0].severity == Severity.MEDIUM


def test_cfg005_redacts_secrets_in_evidence():
    findings = check_cfg005(one({"command": "bash", "args": ["-c", "TOKEN=abc123secret run && x"]}))
    assert "abc123secret" not in findings[0].evidence


def test_cfg005_negative_direct_launch():
    assert check_cfg005(one({"command": "node", "args": ["server.js", "--port", "3000"]})) == []
    assert check_cfg005(one({"command": "/usr/local/bin/my-server"})) == []


# CFG006 ---------------------------------------------------------------------

def test_cfg006_broad_roots_flagged():
    for path in ("/", "~", "$HOME", "/Users/alice", "/home/bob/", "C:\\", "C:\\Users\\alice", "--root=/", "/:/host"):
        cfg = {"command": "npx", "args": ["fs", path]}
        assert ids(check_cfg006(one(cfg))) == ["CFG006"], path


def test_cfg006_negative_specific_directories():
    for path in ("/Users/alice/projects/app", "~/projects", "./src", "/srv/data", "C:\\work\\app", "--port=3000"):
        assert check_cfg006(one({"command": "npx", "args": ["fs", path]})) == [], path

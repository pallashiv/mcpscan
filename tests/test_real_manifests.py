"""Regression tests on real tools/list output from legitimate servers.

These guard against false positives: the servers are Anthropic's reference MCP servers, so
anything noisy here is a rule problem, not a server problem. See fixtures/real/README.md.
"""

from pathlib import Path

import pytest

from mcpscan.scanner import scan_file

FIXTURES = Path(__file__).parent / "fixtures" / "real"

# (rule_id, severity label, subject) for every finding expected on each server.
EXPECTED = {
    "everything": [
        ("MCP004", "high", "tool:get-env"),
        ("MCP005", "low", "manifest"),
    ],
    "filesystem": [
        ("MCP004", "medium", "tool:create_directory"),
        ("MCP004", "medium", "tool:edit_file"),
        ("MCP004", "medium", "tool:move_file"),
        ("MCP004", "medium", "tool:write_file"),
        ("MCP005", "low", "manifest"),  # path, unconstrained
        ("MCP005", "low", "manifest"),  # additionalProperties
        ("MCP007", "low", "tool:read_file"),  # DEPRECATED: use read_text_file
    ],
    "memory": [
        ("MCP005", "low", "manifest"),  # additionalProperties
    ],
    "thinking": [
        ("MCP005", "low", "manifest"),  # additionalProperties
    ],
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_real_server_findings_are_stable(name):
    result = scan_file(str(FIXTURES / f"{name}.json"))
    actual = sorted((f.rule_id, f.severity.label, f.subject) for f in result.findings)
    assert actual == sorted(EXPECTED[name])


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_no_injection_unicode_or_sensitive_file_findings_on_legitimate_servers(name):
    result = scan_file(str(FIXTURES / f"{name}.json"))
    assert not {f.rule_id for f in result.findings} & {"MCP001", "MCP002", "MCP003"}


def test_total_noise_stays_small():
    total = sum(len(scan_file(str(FIXTURES / f"{n}.json")).findings) for n in EXPECTED)
    assert total <= 15  # was 49 before MCP005/MCP007 tuning

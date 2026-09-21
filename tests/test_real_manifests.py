"""Regression tests on real tools/list output from legitimate servers.

These guard against false positives. Every server here is a popular open-source MCP server, so
noise on them is a rule problem, not a server problem. See fixtures/real/README.md.

Expected findings are (rule_id, severity, subject). Each was reviewed by hand; the comments say
why the interesting ones are correct.
"""

from pathlib import Path

import pytest

from mcpscan.models import Severity
from mcpscan.scanner import scan_file

FIXTURES = Path(__file__).parent / "fixtures" / "real"

EXPECTED = {
    "everything": [
        ("MCP004", "high", "tool:get-env"),  # returns environment variables
        ("MCP005", "low", "manifest"),  # additionalProperties
    ],
    "filesystem": [
        ("MCP004", "medium", "tool:create_directory"),
        ("MCP004", "medium", "tool:edit_file"),
        ("MCP004", "medium", "tool:move_file"),
        ("MCP004", "medium", "tool:write_file"),
        ("MCP005", "low", "manifest"),  # path
        ("MCP005", "low", "manifest"),  # additionalProperties
        ("MCP007", "low", "manifest"),  # read_file: "DEPRECATED: use read_text_file"
    ],
    "memory": [("MCP005", "low", "manifest")],
    "thinking": [("MCP005", "low", "manifest")],
    "context7": [
        ("MCP001", "medium", "tool:query-docs"),  # "You must call <resolve tool> first": sequencing
        ("MCP005", "low", "manifest"),
        ("MCP007", "low", "manifest"),
    ],
    "playwright": [
        ("MCP004", "high", "tool:browser_run_code_unsafe"),  # the tool is named "unsafe"
        ("MCP005", "medium", "tool:browser_run_code_unsafe"),  # free-form `code`
        ("MCP005", "low", "manifest"),  # filename
        ("MCP005", "low", "manifest"),  # url
        ("MCP007", "low", "manifest"),
    ],
    "desktop-commander": [
        ("MCP003", "medium", "tool:start_search"),  # ".env" in a list of example filenames
        ("MCP004", "high", "tool:start_process"),  # runs terminal commands
        ("MCP004", "high", "tool:write_file"),  # description says "ANY FILE"
        ("MCP004", "medium", "tool:create_directory"),
        ("MCP004", "medium", "tool:move_file"),
        ("MCP005", "medium", "tool:start_process"),  # command
        ("MCP005", "medium", "tool:start_process"),  # shell
        ("MCP005", "low", "manifest"),  # file_path
        ("MCP005", "low", "manifest"),  # outputPath
        ("MCP005", "low", "manifest"),  # path
        # Real shadowing behaviour: "ALWAYS use this instead of the analysis tool".
        ("MCP007", "medium", "tool:interact_with_process"),
        ("MCP007", "medium", "tool:start_process"),
        ("MCP007", "low", "manifest"),
    ],
    "github": [
        ("MCP005", "low", "manifest"),  # files[].path
        ("MCP005", "low", "manifest"),  # path
        ("MCP006", "low", "manifest"),  # 11 write tools without annotations
    ],
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_real_server_findings_are_stable(name):
    result = scan_file(str(FIXTURES / f"{name}.json"))
    actual = sorted((f.rule_id, f.severity.label, f.subject) for f in result.findings)
    assert actual == sorted(EXPECTED[name])


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_no_high_severity_injection_unicode_or_sensitive_file_findings(name):
    result = scan_file(str(FIXTURES / f"{name}.json"))
    bad = [f for f in result.findings if f.rule_id in {"MCP001", "MCP002", "MCP003"} and f.severity >= Severity.HIGH]
    assert bad == []
    assert not any(f.rule_id == "MCP002" for f in result.findings)


def test_total_noise_stays_small():
    total = sum(len(scan_file(str(FIXTURES / f"{n}.json")).findings) for n in EXPECTED)
    assert total <= 40  # was 106 before the MCP005/006/007 tuning

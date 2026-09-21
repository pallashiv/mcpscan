"""scripts/run-scan.sh, the scan step of the GitHub Action."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "run-scan.sh"
EXAMPLES = ROOT / "examples"

BIN_DIR = Path(sys.executable).parent
pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or not (BIN_DIR / "mcpscan").exists(),
    reason="needs bash and an installed mcpscan console script",
)


def run(tmp_path, path, **env):
    output = tmp_path / "github_output"
    output.unlink(missing_ok=True)  # the script appends, like $GITHUB_OUTPUT within a step
    full_env = {
        **os.environ,
        "PATH": f"{BIN_DIR}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(output),
        "MCPSCAN_PATH": str(path),
        "MCPSCAN_SARIF_FILE": str(tmp_path / "out.sarif"),
        **env,
    }
    proc = subprocess.run(["bash", str(SCRIPT)], env=full_env, capture_output=True, text=True)
    code_line = output.read_text().strip() if output.exists() else ""
    return proc, code_line


def test_findings_reported_via_output_and_step_itself_succeeds(tmp_path):
    proc, out = run(tmp_path, EXAMPLES / "vulnerable_manifest.json")
    assert proc.returncode == 0  # the step never fails; a later step does
    assert out == "exit-code=1"
    assert "MCP001" in proc.stdout
    sarif = json.loads((tmp_path / "out.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]


def test_clean_input_exit_code_zero(tmp_path):
    proc, out = run(tmp_path, EXAMPLES / "safe_manifest.json")
    assert (proc.returncode, out) == (0, "exit-code=0")
    assert (tmp_path / "out.sarif").exists()


def test_fail_on_threshold_is_passed_through(tmp_path):
    _, out = run(tmp_path, EXAMPLES / "vulnerable_config.json", MCPSCAN_FAIL_ON="critical")
    assert out == "exit-code=0"


def test_unusable_input_reports_2_and_writes_no_sarif(tmp_path):
    proc, out = run(tmp_path, tmp_path / "missing.json")
    assert (proc.returncode, out) == (0, "exit-code=2")
    assert not (tmp_path / "out.sarif").exists()


def test_baseline_and_ignore_inputs_are_passed_through(tmp_path):
    baseline = tmp_path / "baseline.json"
    subprocess.run([str(BIN_DIR / "mcpscan"), "scan", str(EXAMPLES / "vulnerable_manifest.json"),
                    "--write-baseline", str(baseline)], capture_output=True, check=True)
    _, out = run(tmp_path, EXAMPLES / "vulnerable_manifest.json", MCPSCAN_BASELINE=str(baseline))
    assert out == "exit-code=0"

    ignore = tmp_path / "ignore.json"
    ignore.write_text(json.dumps({"ignore": [{"rule": "CFG001", "reason": "t"}]}))
    _, out = run(tmp_path, EXAMPLES / "vulnerable_config.json", MCPSCAN_IGNORE_FILE=str(ignore), MCPSCAN_FAIL_ON="critical")
    assert out == "exit-code=0"
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    _, out = run(tmp_path, EXAMPLES / "vulnerable_config.json", MCPSCAN_IGNORE_FILE=str(bad))
    assert out == "exit-code=2"


def test_values_with_spaces_and_shell_metacharacters_are_not_interpreted(tmp_path):
    tricky = tmp_path / "my dir; touch pwned"
    tricky.mkdir()
    manifest = tricky / "m $(id).json"
    manifest.write_text(json.dumps({"tools": []}))
    proc, out = run(tmp_path, manifest)
    assert out == "exit-code=0" and not (tmp_path / "pwned").exists()

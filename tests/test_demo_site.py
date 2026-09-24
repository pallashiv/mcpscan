"""scripts/build_demo_site.py: the generator behind the GitHub Pages live demo.

Output goes into site/examples/, which is gitignored and rebuilt on every deploy (see
.github/workflows/pages.yml) -- this test exercises the same script CI runs.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_demo_site.py"
OUT = ROOT / "site" / "examples"
EXPECTED = ["vulnerable-manifest", "safe-manifest", "vulnerable-config", "rug-pull", "real-server"]


def test_build_script_produces_a_valid_report_per_scenario():
    subprocess.run([sys.executable, str(SCRIPT)], check=True, capture_output=True, text=True, cwd=ROOT)
    for name in EXPECTED:
        path = OUT / f"{name}.html"
        assert path.exists(), name
        html = path.read_text(encoding="utf-8")
        assert html.startswith("<!doctype html>")
        assert "Content-Security-Policy" in html
        payload = json.loads(re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S).group(1))
        assert payload["path"]  # every scenario has a label, even the synthetic rug-pull one


def test_rug_pull_scenario_demonstrates_drift_detection():
    subprocess.run([sys.executable, str(SCRIPT)], check=True, capture_output=True, text=True, cwd=ROOT)
    html = (OUT / "rug-pull.html").read_text(encoding="utf-8")
    payload = json.loads(re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S).group(1))
    rules = {f["rule_id"] for f in payload["findings"]}
    assert "LOCK001" in rules  # the drift itself
    assert rules & {"MCP001", "MCP003"}  # the rewritten text also trips the injection/secrets rules


def test_vulnerable_and_safe_scenarios_differ_as_expected():
    subprocess.run([sys.executable, str(SCRIPT)], check=True, capture_output=True, text=True, cwd=ROOT)
    vuln = json.loads(re.search(r'<script type="application/json" id="data">(.*?)</script>',
                       (OUT / "vulnerable-manifest.html").read_text(encoding="utf-8"), re.S).group(1))
    safe = json.loads(re.search(r'<script type="application/json" id="data">(.*?)</script>',
                       (OUT / "safe-manifest.html").read_text(encoding="utf-8"), re.S).group(1))
    assert vuln["findings"] and not safe["findings"]

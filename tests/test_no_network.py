"""Guards the claims in SECURITY.md: no network, no process execution, no runtime dependencies."""

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "mcpscan"
PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

# Every module the package may import. Adding to this list is a security-relevant change.
ALLOWED_IMPORTS = {
    "__future__", "argparse", "base64", "dataclasses", "enum", "fnmatch", "hashlib", "ipaddress", "json",
    "os", "pathlib", "re", "sys", "typing", "unicodedata", "urllib.parse",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTRS = {("os", "system"), ("os", "popen"), ("os", "exec"), ("os", "spawn"), ("os", "fork")}


def _modules(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module


def test_only_allowed_stdlib_modules_are_imported():
    for path in SRC.rglob("*.py"):
        for module in _modules(ast.parse(path.read_text(encoding="utf-8"))):
            assert module in ALLOWED_IMPORTS or module.split(".")[0] == "mcpscan", f"{path.name} imports {module}"


def test_no_dynamic_execution_or_process_spawning():
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name):
                    assert fn.id not in FORBIDDEN_CALLS, f"{path.name}: {fn.id}()"
                if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                    name = (fn.value.id, fn.attr)
                    assert not any(name[0] == m and name[1].startswith(a) for m, a in FORBIDDEN_ATTRS), f"{path.name}: {name}"


def test_no_runtime_dependencies():
    assert re.search(r"^dependencies\s*=\s*\[\s*\]\s*$", PYPROJECT.read_text(encoding="utf-8"), re.MULTILINE)


def test_guard_actually_catches_a_violation():
    bad = ast.parse("import socket\nimport os\nos.system('x')\neval('1')")
    assert "socket" not in ALLOWED_IMPORTS
    assert "socket" in set(_modules(bad))

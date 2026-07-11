#!/usr/bin/env python3
"""Fail CI when production runtime code starts depending on the paper-only lab tree."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Iterable


SERVER_DIR = Path(__file__).resolve().parent
TOOLING_FILES = {"architecture_audit.py", "audit_exp_readiness.py", "validate_poc_contracts.py"}
KNOWN_OVERSIZED = {
    "agent_orchestrator.py": "split phase handlers, execution service, and reporting state",
    "server.py": "complete application-factory and blueprint extraction",
}


def runtime_python_files() -> Iterable[Path]:
    for path in sorted(SERVER_DIR.rglob("*.py")):
        relative = path.relative_to(SERVER_DIR)
        if (
            path.name.startswith("test_")
            or path.name in TOOLING_FILES
            or "__pycache__" in relative.parts
            or any(part.startswith(".") for part in relative.parts)
        ):
            continue
        yield path


def lab_dependency_violations(path: Path) -> list[dict]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[dict] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "lab" or alias.name.startswith("lab."):
                    violations.append({"line": node.lineno, "kind": "import", "value": alias.name})
        elif isinstance(node, ast.ImportFrom) and (node.module == "lab" or str(node.module or "").startswith("lab.")):
            violations.append({"line": node.lineno, "kind": "import", "value": node.module})
        elif isinstance(node, ast.Call):
            callable_name = ""
            if isinstance(node.func, ast.Name):
                callable_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                callable_name = node.func.attr
            if callable_name not in {"open", "Path", "read_text", "read_bytes"}:
                continue
            for arg in node.args:
                if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                    continue
                value = arg.value.replace("\\", "/").strip()
                if value == "lab" or value.startswith("lab/") or "/lab/" in value:
                    violations.append({"line": node.lineno, "kind": "filesystem", "value": value})
    return violations


def audit(max_lines: int = 1200) -> dict:
    lab_dependencies: list[dict] = []
    oversized: list[dict] = []
    unexpected_oversized: list[dict] = []
    for path in runtime_python_files():
        relative = path.relative_to(SERVER_DIR).as_posix()
        for violation in lab_dependency_violations(path):
            lab_dependencies.append({"file": relative, **violation})
        if len(path.parts) == len(SERVER_DIR.parts) + 1:
            lines = len(path.read_text(encoding="utf-8").splitlines())
            if lines > max_lines:
                item = {
                    "file": relative,
                    "lines": lines,
                    "recommendation": KNOWN_OVERSIZED.get(path.name, "split by responsibility before further growth"),
                }
                oversized.append(item)
                if path.name not in KNOWN_OVERSIZED:
                    unexpected_oversized.append(item)
    return {
        "ok": not lab_dependencies and not unexpected_oversized,
        "lab_dependencies": lab_dependencies,
        "oversized_files": oversized,
        "unexpected_oversized_files": unexpected_oversized,
        "max_lines": max_lines,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-lines", type=int, default=1200)
    args = parser.parse_args()
    report = audit(args.max_lines)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

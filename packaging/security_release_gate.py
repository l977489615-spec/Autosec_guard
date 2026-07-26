#!/usr/bin/env python3
"""Fail customer releases when tracked source contains common secret material."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECRET_PATTERNS = {
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "cloud access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "provider API key": re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "GitHub token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "Google API key": re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b"),
}
SENSITIVE_SUFFIXES = {
    ".db",
    ".db-journal",
    ".db-shm",
    ".db-wal",
    ".sqlite",
    ".sqlite3",
    ".pem",
    ".p12",
    ".pfx",
}
FORBIDDEN_SOURCE = {
    "client-controlled local command": re.compile(rb"\.get\([\"']lab_command[\"']"),
    "automatic SSH host-key trust": re.compile(rb"AutoAddPolicy\s*\("),
    # Construct the signature in parts so this scanner does not flag its own
    # rule definition while still rejecting the exact insecure SSH option.
    "disabled SSH host-key checking": re.compile(
        rb"StrictHostKeyChecking" + rb"=no"
    ),
}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True,
    )
    return [ROOT / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def main() -> int:
    findings: list[str] = []
    for path in tracked_files():
        if not path.exists():
            continue
        relative = path.relative_to(ROOT).as_posix()
        name = path.name.lower()
        if (name == ".env" or name.startswith(".env.") or name == ".env old") and name != ".env.example":
            findings.append(f"tracked environment file: {relative}")
        if path.suffix.lower() in SENSITIVE_SUFFIXES:
            findings.append(f"tracked sensitive file type: {relative}")
        try:
            content = path.read_bytes()
        except OSError:
            continue
        if b"\0" in content[:8192]:
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                findings.append(f"{label}: {relative}")
        if path.suffix == ".py":
            for label, pattern in FORBIDDEN_SOURCE.items():
                if pattern.search(content):
                    findings.append(f"{label}: {relative}")

    workflow = ROOT / ".github" / "workflows" / "edge-workstation-release.yml"
    if workflow.exists():
        workflow_text = workflow.read_text(encoding="utf-8")
        for line_number, line in enumerate(workflow_text.splitlines(), 1):
            match = re.search(r"\buses:\s*[^@\s]+@([^\s#]+)", line)
            if match and not re.fullmatch(r"[0-9a-f]{40}", match.group(1)):
                findings.append(f"unpinned GitHub Action at {workflow.relative_to(ROOT)}:{line_number}")
        if "AUTOSEC_NUITKA_MODE: onefile" not in workflow_text:
            findings.append("customer CI must build Nuitka onefile artifacts")

    build_script = (ROOT / "packaging" / "build_edge_workstation.py").read_text(encoding="utf-8")
    for required in ("--lto=yes", "--python-flag=no_docstrings", "--python-flag=no_asserts"):
        if required not in build_script:
            findings.append(f"missing binary-hardening option: {required}")
    vite_config = (ROOT / "client" / "vite.config.ts").read_text(encoding="utf-8")
    if "sourcemap: false" not in vite_config:
        findings.append("frontend source maps must be disabled")

    if findings:
        print("Release security gate failed:", file=sys.stderr)
        for finding in sorted(set(findings)):
            print(f"- {finding}", file=sys.stderr)
        return 1
    print("Release secret and workflow pinning gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Controlled template for sensitive file names in extracted app data."""
from __future__ import annotations

import os
from pathlib import Path

POC_TAG = "125. 应用本地敏感文件存储检测"


SENSITIVE_NAMES = ("token", "secret", "credential", "password", "private", "debug")


def main() -> bool:
    root = Path(os.environ.get("AUTOSEC_APP_DATA_FIXTURE_DIR", ""))
    if not root.is_dir():
        print("[INFO] no app data fixture directory supplied")
        return False
    hits = [str(path) for path in root.rglob("*") if any(name in path.name.lower() for name in SENSITIVE_NAMES)]
    print("[RESULT] sensitive file name hits:", hits[:20])
    return bool(hits)


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

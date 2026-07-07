#!/usr/bin/env python3
"""Controlled template for plaintext SQLite artifact discovery."""
from __future__ import annotations

import os
from pathlib import Path

POC_TAG = "123. SQLite 明文敏感数据存储检测"


KEYWORDS = ("password", "token", "session", "vin", "phone", "location")


def main() -> bool:
    root = Path(os.environ.get("AUTOSEC_SQLITE_FIXTURE_DIR", ""))
    if not root.is_dir():
        print("[INFO] no SQLite fixture directory supplied")
        return False
    hits = []
    for path in root.rglob("*"):
        if path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
            continue
        blob = path.read_bytes()[:262144].decode("utf-8", errors="ignore").lower()
        if any(keyword in blob for keyword in KEYWORDS):
            hits.append(str(path))
    print("[RESULT] plaintext SQLite hits:", hits)
    return bool(hits)


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

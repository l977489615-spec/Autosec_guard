#!/usr/bin/env python3
"""Offline lint for UDS negative response logs."""
from __future__ import annotations

import os
import re
from pathlib import Path

POC_TAG = "137. UDS 负响应与安全访问日志检测"


def main() -> bool:
    path = Path(os.environ.get("AUTOSEC_UDS_LOG_FIXTURE", ""))
    text = path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else os.environ.get("AUTOSEC_UDS_LOG_TEXT", "")
    if not text:
        print("[INFO] no UDS log fixture supplied")
        return False
    hit = bool(re.search(r"\b7F\s+(27|10|11|22|31)\s+(33|35|36|37|78)\b", text, re.I))
    print("[RESULT] security-relevant UDS negative response:", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

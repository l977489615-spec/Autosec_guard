#!/usr/bin/env python3
"""Static template for SQL concatenation anti-patterns."""
from __future__ import annotations

import os
import re

POC_TAG = "124. SQL 拼接注入风险模式检测"


def main() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    pattern = r"(rawQuery|execSQL)\s*\([^)]*(SELECT|UPDATE|DELETE|INSERT)[^)]*(\+|String\.format)"
    hit = bool(re.search(pattern, text, re.I | re.S))
    print("[RESULT] SQL concatenation pattern:", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

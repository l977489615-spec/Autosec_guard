#!/usr/bin/env python3
"""Static template for predictable random seed usage."""
from __future__ import annotations

import os
import re

POC_TAG = "133. 伪随机数固定种子风险检测"


def main() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    hit = bool(re.search(r"new\s+Random\s*\(\s*\d+\s*\)|setSeed\s*\(\s*\d+\s*\)", text, re.I))
    print("[RESULT] predictable random seed:", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

#!/usr/bin/env python3
"""Static template for weak crypto mode usage."""
from __future__ import annotations

import os
import re

POC_TAG = "132. 弱加密 ECB/静态 IV 使用检测"


def main() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    hit = bool(re.search(r"AES/ECB|DES/ECB|IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*16\s*\]", text, re.I))
    print("[RESULT] weak crypto pattern:", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

#!/usr/bin/env python3
"""Static check template for WebView JavaScript enablement."""
from __future__ import annotations

import os
import re

POC_TAG = "121. WebView JavaScript 启用风险检测"


def main() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    hit = bool(re.search(r"setJavaScriptEnabled\s*\(\s*true\s*\)", text, re.I))
    print("[RESULT] setJavaScriptEnabled(true):", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

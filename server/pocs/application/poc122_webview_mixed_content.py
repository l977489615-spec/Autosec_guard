#!/usr/bin/env python3
"""Static check template for permissive WebView mixed content mode."""
from __future__ import annotations

import os
import re

POC_TAG = "122. WebView MixedContent 兼容模式检测"


def main() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    hit = bool(re.search(r"MIXED_CONTENT_ALWAYS_ALLOW|setMixedContentMode\s*\(\s*0\s*\)", text, re.I))
    print("[RESULT] permissive mixed content:", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

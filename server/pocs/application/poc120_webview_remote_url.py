#!/usr/bin/env python3
"""Static check template for WebView remote URL loading."""
from __future__ import annotations

import os
import re

POC_TAG = "120. WebView 远程 URL 加载受控检测"


def _fixture_text() -> str:
    path = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if path and os.path.isfile(path):
        return open(path, "r", encoding="utf-8", errors="ignore").read()
    return os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")


def main() -> bool:
    text = _fixture_text()
    if not text:
        print("[INFO] no source fixture supplied; template recorded as controlled check")
        return False
    hit = bool(re.search(r"loadUrl\s*\(\s*[\"']https?://", text, re.I))
    print("[RESULT] WebView remote URL pattern:", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

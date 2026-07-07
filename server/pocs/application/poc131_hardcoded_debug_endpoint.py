#!/usr/bin/env python3
"""Static template for hardcoded debug or staging endpoints."""
from __future__ import annotations

import os
import re

POC_TAG = "131. 硬编码调试接口与测试域名检测"


def main() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    pattern = r"https?://[^\"'\s]*(debug|dev|test|staging|mock|internal)[^\"'\s]*"
    hits = re.findall(pattern, text, re.I)
    print("[RESULT] hardcoded debug endpoint count:", len(hits))
    return bool(hits)


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

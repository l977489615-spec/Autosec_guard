#!/usr/bin/env python3
"""Manifest template for exported Activity with intent-filter."""
from __future__ import annotations

import os
import re

POC_TAG = "126. Exported Activity Intent-Filter 风险检测"


def main() -> bool:
    manifest = os.environ.get("AUTOSEC_ANDROID_MANIFEST_TEXT", "")
    path = os.environ.get("AUTOSEC_ANDROID_MANIFEST", "")
    if path and os.path.isfile(path):
        manifest = open(path, "r", encoding="utf-8", errors="ignore").read()
    pattern = r"<activity\b(?=[\s\S]*?android:exported\s*=\s*[\"']true[\"'])(?=[\s\S]*?<intent-filter)"
    hit = bool(re.search(pattern, manifest, re.I))
    print("[RESULT] exported activity with intent-filter:", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

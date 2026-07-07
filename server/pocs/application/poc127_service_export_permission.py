#!/usr/bin/env python3
"""Manifest template for exported Service missing custom permission."""
from __future__ import annotations

import os
import re

POC_TAG = "127. Exported Service 缺少权限保护检测"


def main() -> bool:
    manifest = os.environ.get("AUTOSEC_ANDROID_MANIFEST_TEXT", "")
    path = os.environ.get("AUTOSEC_ANDROID_MANIFEST", "")
    if path and os.path.isfile(path):
        manifest = open(path, "r", encoding="utf-8", errors="ignore").read()
    services = re.findall(r"<service\b[^>]*>", manifest, re.I)
    hit = any("exported=\"true\"" in item and "permission=" not in item for item in services)
    print("[RESULT] exported service without permission:", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

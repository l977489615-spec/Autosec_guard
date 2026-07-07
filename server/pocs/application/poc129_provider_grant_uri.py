#!/usr/bin/env python3
"""Manifest template for exported Provider or permissive grantUriPermissions."""
from __future__ import annotations

import os
import re

POC_TAG = "129. Provider 导出与 grantUriPermissions 风险检测"


def main() -> bool:
    manifest = os.environ.get("AUTOSEC_ANDROID_MANIFEST_TEXT", "")
    path = os.environ.get("AUTOSEC_ANDROID_MANIFEST", "")
    if path and os.path.isfile(path):
        manifest = open(path, "r", encoding="utf-8", errors="ignore").read()
    providers = re.findall(r"<provider\b[^>]*>", manifest, re.I)
    hit = any("exported=\"true\"" in item or "granturipermissions=\"true\"" in item.lower() for item in providers)
    print("[RESULT] provider exposure pattern:", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

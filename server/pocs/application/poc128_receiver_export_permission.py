#!/usr/bin/env python3
"""Manifest template for exported BroadcastReceiver missing permission."""
from __future__ import annotations

import os
import re

POC_TAG = "128. Exported Receiver 缺少权限保护检测"


def main() -> bool:
    manifest = os.environ.get("AUTOSEC_ANDROID_MANIFEST_TEXT", "")
    path = os.environ.get("AUTOSEC_ANDROID_MANIFEST", "")
    if path and os.path.isfile(path):
        manifest = open(path, "r", encoding="utf-8", errors="ignore").read()
    receivers = re.findall(r"<receiver\b[^>]*>", manifest, re.I)
    hit = any("exported=\"true\"" in item and "permission=" not in item for item in receivers)
    print("[RESULT] exported receiver without permission:", "FOUND" if hit else "not found")
    return hit


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

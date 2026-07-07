#!/usr/bin/env python3
"""Controlled template for sensitive keywords in app/system logs."""
from __future__ import annotations

import os

POC_TAG = "130. 调试日志敏感信息泄露检测"


KEYWORDS = ("password", "passwd", "token", "secret", "session", "authorization", "vin")


def main() -> bool:
    text = os.environ.get("AUTOSEC_LOG_TEXT", "")
    path = os.environ.get("AUTOSEC_LOG_FIXTURE", "")
    if path and os.path.isfile(path):
        text = open(path, "r", encoding="utf-8", errors="ignore").read()
    lowered = text.lower()
    hits = [keyword for keyword in KEYWORDS if keyword in lowered]
    print("[RESULT] sensitive log keywords:", hits)
    return bool(hits)


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

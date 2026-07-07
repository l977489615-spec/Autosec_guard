#!/usr/bin/env python3
"""Offline lint for CAN replay logs before any bus transmission."""
from __future__ import annotations

import os
import re
from pathlib import Path

POC_TAG = "136. CAN 重放日志安全 Lint"


def main() -> bool:
    path = Path(os.environ.get("AUTOSEC_CAN_LOG_FIXTURE", ""))
    if not path.is_file():
        print("[INFO] no CAN log fixture supplied")
        return False
    text = path.read_text(encoding="utf-8", errors="ignore")
    ids = [int(match, 16) for match in re.findall(r"\b([0-7][0-9A-Fa-f]{2})\b", text)]
    suspicious = [hex(can_id) for can_id in ids if can_id < 0x100 or can_id in {0x7DF, 0x7E0, 0x7E8}]
    print("[RESULT] suspicious replay IDs:", suspicious[:20])
    return bool(suspicious)


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

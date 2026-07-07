#!/usr/bin/env python3
"""Safe DoIP entity status probe template."""
from __future__ import annotations

import os
import socket

POC_TAG = "134. DoIP Entity Status 安全探测"


def main() -> bool:
    host = os.environ.get("AUTOSEC_TARGET_IP") or os.environ.get("TARGET_IP") or "127.0.0.1"
    port = int(os.environ.get("AUTOSEC_DOIP_PORT", "13400"))
    try:
        with socket.create_connection((host, port), timeout=1.5):
            print(f"[RESULT] DoIP port reachable: {host}:{port}")
            return True
    except OSError as exc:
        print(f"[INFO] DoIP port not reachable: {host}:{port} ({exc})")
        return False


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

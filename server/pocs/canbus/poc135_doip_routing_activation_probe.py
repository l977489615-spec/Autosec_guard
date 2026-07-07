#!/usr/bin/env python3
"""Safe DoIP routing activation pre-check without diagnostic payloads."""
from __future__ import annotations

import os
import socket

POC_TAG = "135. DoIP Routing Activation 前置条件检测"


def main() -> bool:
    host = os.environ.get("AUTOSEC_TARGET_IP") or os.environ.get("TARGET_IP") or "127.0.0.1"
    port = int(os.environ.get("AUTOSEC_DOIP_PORT", "13400"))
    try:
        with socket.create_connection((host, port), timeout=1.5) as sock:
            sock.settimeout(1.0)
            sock.sendall(b"\x02\xfd\x00\x05\x00\x00\x00\x00")
            print(f"[RESULT] sent zero-length DoIP routing pre-check to {host}:{port}")
            return True
    except OSError as exc:
        print(f"[INFO] DoIP routing pre-check skipped: {exc}")
        return False


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)

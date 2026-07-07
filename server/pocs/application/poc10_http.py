#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检测设备 app 是否允许不安全的明文 HTTP 通信（usesCleartextTraffic）。"""
from __future__ import annotations

import argparse
import logging
import re
import sys

from _experiment.apk_manifest import check_manifest, run_apk_manifest_check

POC_TAG = "10. 检测设备app是否允许不安全的明文通信..."
PATTERN = re.compile(r'\b(?:android:)?usesCleartextTraffic\s*=\s*"true"', re.IGNORECASE)


def main() -> bool:
    parser = argparse.ArgumentParser(description="检测 usesCleartextTraffic=true")
    parser.add_argument("--serial", help="ADB serial")
    args = parser.parse_args()

    vulnerable, message = run_apk_manifest_check(
        device_serial=args.serial,
        vulnerable_if=lambda path: check_manifest(path, PATTERN),
    )
    logging.warning(message)
    return vulnerable


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    raise SystemExit(0 if main() else 1)

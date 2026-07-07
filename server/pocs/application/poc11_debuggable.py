#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检测设备 app 是否允许不安全的动态调试（android:debuggable=true）。"""
from __future__ import annotations

import argparse
import logging
import re
import sys

from _experiment.apk_manifest import check_manifest, run_apk_manifest_check

POC_TAG = "11. 检测设备app是否允许不安全的动态调试..."
PATTERN = re.compile(r'\b(?:android:)?debuggable\s*=\s*"true"', re.IGNORECASE)


def main() -> bool:
    parser = argparse.ArgumentParser(description="检测 debuggable=true")
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

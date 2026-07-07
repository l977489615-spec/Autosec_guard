#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检测设备 app 是否允许不安全的应用数据备份（allowBackup=true）。"""
from __future__ import annotations

import argparse
import logging
import re
import sys

from _experiment.apk_manifest import check_manifest, run_apk_manifest_check

POC_TAG = "12. 检测设备app是否允许不安全的应用数据备份和还原..."
PATTERN = re.compile(r'\b(?:android:)?allowBackup\s*=\s*"true"', re.IGNORECASE)


def run_check() -> bool:
    parser = argparse.ArgumentParser(description="检测 allowBackup=true")
    parser.add_argument("--serial", help="ADB serial")
    args = parser.parse_args()

    vulnerable, message = run_apk_manifest_check(
        device_serial=args.serial,
        vulnerable_if=lambda path: check_manifest(path, PATTERN),
    )
    logging.warning(message)
    return vulnerable


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc12AllowbackupPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备app是否允许不安全的应用数据备份和还原...'
    meta_cve_id = 'CWE-530'
    meta_severity = 'Medium'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['application']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

#!/usr/bin/env python3
"""Controlled template for sensitive file names in extracted app data."""
from __future__ import annotations

import os
from pathlib import Path

POC_TAG = "125. 应用本地敏感文件存储检测"


SENSITIVE_NAMES = ("token", "secret", "credential", "password", "private", "debug")


def run_check() -> bool:
    root = Path(os.environ.get("AUTOSEC_APP_DATA_FIXTURE_DIR", ""))
    if not root.is_dir():
        print("[INFO] no app data fixture directory supplied")
        return False
    hits = [str(path) for path in root.rglob("*") if any(name in path.name.lower() for name in SENSITIVE_NAMES)]
    print("[RESULT] sensitive file name hits:", hits[:20])
    return bool(hits)


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc125SensitiveFileStoragePlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '应用本地敏感文件存储检测'
    meta_cve_id = 'CWE-922'
    meta_severity = 'High'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['app_data_fixture_dir']
    meta_profiles = ['application']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

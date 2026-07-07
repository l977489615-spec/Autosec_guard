#!/usr/bin/env python3
"""Controlled template for plaintext SQLite artifact discovery."""
from __future__ import annotations

import os
from pathlib import Path

POC_TAG = "123. SQLite 明文敏感数据存储检测"


KEYWORDS = ("password", "token", "session", "vin", "phone", "location")


def run_check() -> bool:
    root = Path(os.environ.get("AUTOSEC_SQLITE_FIXTURE_DIR", ""))
    if not root.is_dir():
        print("[INFO] no SQLite fixture directory supplied")
        return False
    hits = []
    for path in root.rglob("*"):
        if path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
            continue
        blob = path.read_bytes()[:262144].decode("utf-8", errors="ignore").lower()
        if any(keyword in blob for keyword in KEYWORDS):
            hits.append(str(path))
    print("[RESULT] plaintext SQLite hits:", hits)
    return bool(hits)


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc123SqlitePlaintextPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = 'SQLite 明文敏感数据存储检测'
    meta_cve_id = 'CWE-312'
    meta_severity = 'High'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['sqlite_fixture_dir']
    meta_profiles = ['application']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

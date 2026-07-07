#!/usr/bin/env python3
"""Offline lint for UDS negative response logs."""
from __future__ import annotations

import os
import re
from pathlib import Path

POC_TAG = "137. UDS 负响应与安全访问日志检测"


def run_check() -> bool:
    path = Path(os.environ.get("AUTOSEC_UDS_LOG_FIXTURE", ""))
    text = path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else os.environ.get("AUTOSEC_UDS_LOG_TEXT", "")
    if not text:
        print("[INFO] no UDS log fixture supplied")
        return False
    hit = bool(re.search(r"\b7F\s+(27|10|11|22|31)\s+(33|35|36|37|78)\b", text, re.I))
    print("[RESULT] security-relevant UDS negative response:", "FOUND" if hit else "not found")
    return hit


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc137UdsNegativeResponseLintPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = 'UDS 负响应与安全访问日志检测'
    meta_cve_id = 'CWE-209'
    meta_severity = 'Medium'
    meta_protocol = 'uds'
    meta_target_os = ['all']
    meta_required_params = ['uds_log_fixture']
    meta_profiles = ['can_extended']
    meta_attack_surface = 'CAN/UDS/OBD'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

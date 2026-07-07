#!/usr/bin/env python3
"""Offline lint for CAN replay logs before any bus transmission."""
from __future__ import annotations

import os
import re
from pathlib import Path

POC_TAG = "136. CAN 重放日志安全 Lint"


def run_check() -> bool:
    path = Path(os.environ.get("AUTOSEC_CAN_LOG_FIXTURE", ""))
    if not path.is_file():
        print("[INFO] no CAN log fixture supplied")
        return False
    text = path.read_text(encoding="utf-8", errors="ignore")
    ids = [int(match, 16) for match in re.findall(r"\b([0-7][0-9A-Fa-f]{2})\b", text)]
    suspicious = [hex(can_id) for can_id in ids if can_id < 0x100 or can_id in {0x7DF, 0x7E0, 0x7E8}]
    print("[RESULT] suspicious replay IDs:", suspicious[:20])
    return bool(suspicious)


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc136CanLogReplaySafetyLintPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = 'CAN 重放日志安全 Lint'
    meta_cve_id = 'CWE-294'
    meta_severity = 'Medium'
    meta_protocol = 'can'
    meta_target_os = ['all']
    meta_required_params = ['can_log_fixture']
    meta_profiles = ['can_extended']
    meta_attack_surface = 'CAN/UDS/OBD'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

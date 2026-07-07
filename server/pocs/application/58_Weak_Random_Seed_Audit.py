#!/usr/bin/env python3
"""Static template for predictable random seed usage."""
from __future__ import annotations

import os
import re

POC_TAG = "133. 伪随机数固定种子风险检测"


def run_check() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    hit = bool(re.search(r"new\s+Random\s*\(\s*\d+\s*\)|setSeed\s*\(\s*\d+\s*\)", text, re.I))
    print("[RESULT] predictable random seed:", "FOUND" if hit else "not found")
    return hit


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc133WeakRandomSeedPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '伪随机数固定种子风险检测'
    meta_cve_id = 'CWE-337'
    meta_severity = 'Medium'
    meta_protocol = 'crypto'
    meta_target_os = ['android']
    meta_required_params = ['android_source_fixture']
    meta_profiles = ['application']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

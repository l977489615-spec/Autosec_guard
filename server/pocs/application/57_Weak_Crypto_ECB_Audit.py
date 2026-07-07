#!/usr/bin/env python3
"""Static template for weak crypto mode usage."""
from __future__ import annotations

import os
import re

POC_TAG = "132. 弱加密 ECB/静态 IV 使用检测"


def run_check() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    hit = bool(re.search(r"AES/ECB|DES/ECB|IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*16\s*\]", text, re.I))
    print("[RESULT] weak crypto pattern:", "FOUND" if hit else "not found")
    return hit


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc132WeakCryptoEcbPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '弱加密 ECB/静态 IV 使用检测'
    meta_cve_id = 'CWE-327'
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

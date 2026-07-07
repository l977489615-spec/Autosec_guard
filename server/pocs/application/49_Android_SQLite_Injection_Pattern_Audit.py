#!/usr/bin/env python3
"""Static template for SQL concatenation anti-patterns."""
from __future__ import annotations

import os
import re

POC_TAG = "124. SQL 拼接注入风险模式检测"


def run_check() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    pattern = r"(rawQuery|execSQL)\s*\([^)]*(SELECT|UPDATE|DELETE|INSERT)[^)]*(\+|String\.format)"
    hit = bool(re.search(pattern, text, re.I | re.S))
    print("[RESULT] SQL concatenation pattern:", "FOUND" if hit else "not found")
    return hit


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc124SqliteInjectionPatternPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = 'SQL 拼接注入风险模式检测'
    meta_cve_id = 'CWE-89'
    meta_severity = 'High'
    meta_protocol = 'android'
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

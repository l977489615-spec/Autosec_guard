#!/usr/bin/env python3
"""Controlled template for sensitive keywords in app/system logs."""
from __future__ import annotations

import os

POC_TAG = "130. 调试日志敏感信息泄露检测"


KEYWORDS = ("password", "passwd", "token", "secret", "session", "authorization", "vin")


def run_check() -> bool:
    text = os.environ.get("AUTOSEC_LOG_TEXT", "")
    path = os.environ.get("AUTOSEC_LOG_FIXTURE", "")
    if path and os.path.isfile(path):
        text = open(path, "r", encoding="utf-8", errors="ignore").read()
    lowered = text.lower()
    hits = [keyword for keyword in KEYWORDS if keyword in lowered]
    print("[RESULT] sensitive log keywords:", hits)
    return bool(hits)


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc130DebugLogSensitivePlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '调试日志敏感信息泄露检测'
    meta_cve_id = 'CWE-532'
    meta_severity = 'Medium'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['log_fixture']
    meta_profiles = ['application']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

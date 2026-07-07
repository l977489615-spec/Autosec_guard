#!/usr/bin/env python3
"""Static template for hardcoded debug or staging endpoints."""
from __future__ import annotations

import os
import re

POC_TAG = "131. 硬编码调试接口与测试域名检测"


def run_check() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    pattern = r"https?://[^\"'\s]*(debug|dev|test|staging|mock|internal)[^\"'\s]*"
    hits = re.findall(pattern, text, re.I)
    print("[RESULT] hardcoded debug endpoint count:", len(hits))
    return bool(hits)


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc131HardcodedDebugEndpointPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '硬编码调试接口与测试域名检测'
    meta_cve_id = 'CWE-489'
    meta_severity = 'Medium'
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

#!/usr/bin/env python3
"""Manifest template for exported Service missing custom permission."""
from __future__ import annotations

import os
import re

POC_TAG = "127. Exported Service 缺少权限保护检测"


def run_check() -> bool:
    manifest = os.environ.get("AUTOSEC_ANDROID_MANIFEST_TEXT", "")
    path = os.environ.get("AUTOSEC_ANDROID_MANIFEST", "")
    if path and os.path.isfile(path):
        manifest = open(path, "r", encoding="utf-8", errors="ignore").read()
    services = re.findall(r"<service\b[^>]*>", manifest, re.I)
    hit = any("exported=\"true\"" in item and "permission=" not in item for item in services)
    print("[RESULT] exported service without permission:", "FOUND" if hit else "not found")
    return hit


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc127ServiceExportPermissionPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = 'Exported Service 缺少权限保护检测'
    meta_cve_id = 'CWE-926'
    meta_severity = 'High'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['android_manifest']
    meta_profiles = ['application']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

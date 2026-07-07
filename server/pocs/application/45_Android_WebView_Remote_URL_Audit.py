#!/usr/bin/env python3
"""Static check template for WebView remote URL loading."""
from __future__ import annotations

import os
import re

POC_TAG = "120. WebView 远程 URL 加载受控检测"


def _fixture_text() -> str:
    path = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if path and os.path.isfile(path):
        return open(path, "r", encoding="utf-8", errors="ignore").read()
    return os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")


def run_check() -> bool:
    text = _fixture_text()
    if not text:
        print("[INFO] no source fixture supplied; template recorded as controlled check")
        return False
    hit = bool(re.search(r"loadUrl\s*\(\s*[\"']https?://", text, re.I))
    print("[RESULT] WebView remote URL pattern:", "FOUND" if hit else "not found")
    return hit


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc120WebviewRemoteUrlPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = 'WebView 远程 URL 加载受控检测'
    meta_cve_id = 'CWE-829'
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

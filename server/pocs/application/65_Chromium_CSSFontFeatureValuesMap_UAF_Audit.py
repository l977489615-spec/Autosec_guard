#!/usr/bin/env python3
"""Safe exposure audit for Chromium CSSFontFeatureValuesMap UAF risk."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": "POC-LAB-007",
    "cve": "CVE-2026-2441",
    "year": 2026,
    "domain": "IVI浏览器/WebView",
    "vendor_product": "Chrome / Chromium-based browsers",
    "component": "Blink CSSFontFeatureValuesMap",
    "type": "Use-After-Free/RCE",
    "summary": "Chromium Blink CSSFontFeatureValuesMap 迭代器 UAF 可由恶意 HTML 触发，车机浏览器、WebView、投屏浏览组件和 Android Automotive 环境需排查。",
    "source_description": "poc-lab describes a CSSFontFeatureValuesMap iterator use-after-free affecting Chrome/Chromium before fixed versions.",
    "poc_status": "poc-lab公开复现；本插件仅做安全暴露审计",
    "research_value": "车机 WebView/浏览器是 IVI 常见攻击面，Chromium 版本滞后会放大远程内容风险。",
    "source_url": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-2441%20Chrome%20CSSFontFeatureValuesMap%20UAF",
    "references": ["https://github.com/Unclecheng-li/poc-lab"],
    "affected": [
        {"vendor": "Google", "product": "Chrome", "versions": [{"version": "0", "status": "affected", "lessThan": "145.0.7632.75"}]},
        {"vendor": "Chromium", "product": "Chromium", "versions": [{"version": "0", "status": "affected", "lessThan": "145.0.7632.75"}]},
    ],
    "signature_tokens": [
        "CVE-2026-2441", "Chrome", "Chromium", "Blink", "CSSFontFeatureValuesMap",
        "WebView", "Android System WebView", "145.0.7632.75", "UAF",
        "Use After Free",
    ],
}


class ChromiumCSSFontFeatureValuesMapUAFAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-065"
    meta_poc_name = "Chromium CSSFontFeatureValuesMap UAF Audit"
    meta_cve_id = "CVE-2026-2441"
    meta_severity = "High"
    meta_protocol = "local"
    meta_target_os = ["android", "linux", "all"]
    meta_required_params = ["software_inventory_text"]
    meta_profiles = ["application", "browser", "webview"]
    meta_source_url = VULN["source_url"]
    meta_attack_surface = "IVI浏览器/WebView"
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

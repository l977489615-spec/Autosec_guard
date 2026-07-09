#!/usr/bin/env python3
"""
PoC Name: Android Bluetooth L2CAP UAF RCE Audit
CVE: CVE-2021-0475
Category: Wireless
Severity: Critical
Reference: https://nvd.nist.gov/vuln/detail/CVE-2021-0475
"""
from __future__ import annotations

import sys

from iv_plugin_base import IVIVulnerabilityPlugin
from wireless_cve_audit import android_exposure


VULN = {
    "id":             0,
    "cve":            "CVE-2021-0475",
    "year":           2021,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "BT Android L2CAP UAF RCE Audit",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2021-0475",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2021-0475"],
    "signature_tokens": ["CVE-2021-0475"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2021-0475 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2021-0475") if vuln else "CVE-2021-0475",
        "target":    getattr(plugin, "target_ip", "unknown"),
        "technique": "legacy exploit() wrapper",
        "raw":       str(result)[:300],
    }

    # 根据是否有主动网络调用推断等级
    level = "B" if vulnerable is True else ("C" if vulnerable is False else "D")
    try:
        from probe_utils import detection_confidence as _detection_confidence
        return _detection_confidence(level, evidence, vulnerable=vulnerable)
    except ImportError:
        return {
            "detection_confidence": {
                "level": level, "vulnerable": vulnerable,
                "evidence": evidence, "method": "legacy_wrapper",
            }
        }


class BTAndroidL2CAPUAFRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-030"
    meta_poc_name = 'CVE-2021-0475 BT Android L2CAP UAF RCE Active Validation'
    meta_cve_id = "CVE-2021-0475"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2021-0475"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2021-0475']
    meta_severity = "Critical"
    meta_protocol = "bluetooth"
    meta_target_os = ["android"]
    meta_required_params = ["bluetooth_mac"]
    meta_profiles = ["bluetooth"]
    is_disruptive = True
    meta_destructive_level = "Restart"

    def check_prerequisites(self):
        self.target_mac = self.params.get("bluetooth_mac") or self.params.get("target_mac")
        if not self.target_mac:
            raise RuntimeError("需要 bluetooth_mac 或 target_mac")
        return True

    def exploit(self):
        vulnerable, evidence = android_exposure(
            self.params, {"10", "11"}, "2021-05-01"
        )
        evidence = f"target={self.target_mac}; {evidence}"
        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "Android L2CAP use-after-free RCE active validation",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    params = {"bluetooth_mac": sys.argv[1]} if len(sys.argv) > 1 else {}
    BTAndroidL2CAPUAFRCEAuditPlugin(params).run_verify()

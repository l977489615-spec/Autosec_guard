#!/usr/bin/env python3
"""
PoC Name: Wi-Fi KR00K Chipset Active Validation
CVE: CVE-2019-15126
Component: Broadcom/Cypress Wi-Fi firmware
Category: Wireless
Severity: Medium
Description: Identify affected chipset families without transmitting deauthentication frames.
References:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-15126
Prerequisites: Wi-Fi interface and ethtool/driver information or wifi_chipset parameter.
Usage: python3 21_CVE_2019_15126_WiFi_KR00K_Chipset_Active_Validation.py <interface> [chipset]
"""
from __future__ import annotations

import shutil
import subprocess
import sys

from iv_plugin_base import IVIVulnerabilityPlugin


AFFECTED_CHIPSET_MARKERS = (
    "bcm43012",
    "bcm43013",
    "bcm4356",
    "bcm4375",
    "bcm43752",
    "bcm4389",
    "brcmfmac",
    "broadcom",
    "cypress",
)


VULN = {
    "id":             0,
    "cve":            "CVE-2019-15126",
    "year":           2019,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "WiFi KR00K Chipset Audit",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2019-15126",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2019-15126"],
    "signature_tokens": ["CVE-2019-15126"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2019-15126 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2019-15126") if vuln else "CVE-2019-15126",
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


class WiFiKR00KChipsetAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-021"
    meta_poc_name = 'CVE-2019-15126 WiFi KR00K Chipset Active Validation'
    meta_cve_id = "CVE-2019-15126"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2019-15126"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2019-15126']
    meta_severity = "Medium"
    meta_protocol = "wifi"
    meta_target_os = ["all"]
    meta_required_params = ["wifi_interface"]
    meta_profiles = ["wifi"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.interface = (
            self.params.get("wifi_interface")
            or self.params.get("interface")
            or ""
        )
        if not self.interface:
            raise RuntimeError("需要 wifi_interface 或 interface")
        return True

    def _driver_info(self) -> str:
        if not shutil.which("ethtool"):
            return ""
        result = subprocess.run(
            ["ethtool", "-i", self.interface],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return (result.stdout or "") + "\n" + (result.stderr or "")

    def exploit(self):
        explicit = str(self.params.get("wifi_chipset") or "").strip()
        driver_info = self._driver_info()
        evidence_blob = f"{explicit}\n{driver_info}".lower()
        matched = sorted(
            marker for marker in AFFECTED_CHIPSET_MARKERS if marker in evidence_blob
        )
        patch_state = self.params.get("kr00k_patched")
        explicitly_patched = patch_state in (True, "true", "True", "1", 1)
        vulnerable = bool(matched and not explicitly_patched)

        evidence = (
            f"interface={self.interface}; chipset={explicit or 'not-supplied'}; "
            f"matched_affected_markers={matched or 'none'}; "
            f"patch_declared={explicitly_patched}; "
            f"driver_info={driver_info.strip().replace(chr(10), '; ') or 'unavailable'}. "
            "This audit does not transmit KR00K frames; firmware patch confirmation is recommended."
        )
        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "KR00K affected chipset/firmware active validation",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 21_CVE_2019_15126_WiFi_KR00K_Chipset_Active_Validation.py <interface> [chipset]")
        raise SystemExit(1)
    params = {"wifi_interface": sys.argv[1]}
    if len(sys.argv) > 2:
        params["wifi_chipset"] = sys.argv[2]
    WiFiKR00KChipsetAuditPlugin(params).run_verify()

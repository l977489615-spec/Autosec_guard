"""
PoC Name: Wi-Fi EAP-PWD Cache Side-Channel Audit
CVE: CVE-2019-9495
Category: Wireless
Severity: Medium
Reference: https://nvd.nist.gov/vuln/detail/CVE-2019-9495
"""
from __future__ import annotations

import sys

from iv_plugin_base import IVIVulnerabilityPlugin
from wireless_cve_audit import as_bool, local_version, version_tuple


class WiFiEAPPWDCacheAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-027"
    meta_poc_name = "WiFi EAP PWD Cache Audit"
    meta_cve_id = "CVE-2019-9495"
    meta_severity = "Medium"
    meta_protocol = "wifi"
    meta_target_os = ["all"]
    meta_required_params = ["wifi_interface"]
    meta_profiles = ["wifi"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.interface = self.params.get("wifi_interface") or self.params.get("interface")
        if not self.interface:
            raise RuntimeError("需要 wifi_interface 或 interface")
        return True

    def exploit(self):
        version = local_version(
            self.params.get("wpa_supplicant_version"), "wpa_supplicant", "-v"
        )
        enabled = as_bool(self.params.get("eap_pwd_enabled"))
        affected = bool(version_tuple(version) and version_tuple(version) <= (2, 7, 0))
        vulnerable = bool(affected and enabled is True)
        evidence = (
            f"interface={self.interface}; version={version or 'unknown'}; "
            f"eap_pwd_enabled={enabled}; affected_through_2_7={affected}. "
            "No cache observation or password cracking was attempted."
        )
        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "EAP-PWD cache side-channel exposure audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    params = {"wifi_interface": sys.argv[1]} if len(sys.argv) > 1 else {}
    WiFiEAPPWDCacheAuditPlugin(params).run_verify()

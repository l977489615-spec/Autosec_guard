"""
PoC Name: Wi-Fi EAP-PWD Client Session Takeover Audit
CVE: CVE-2019-9499
Category: Wireless
Severity: High
Reference: https://nvd.nist.gov/vuln/detail/CVE-2019-9499
"""
from __future__ import annotations

import sys

from iv_plugin_base import IVIVulnerabilityPlugin
from wireless_cve_audit import as_bool, local_version, version_tuple


class WiFiEAPPWDClientTakeoverAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-029"
    meta_poc_name = "WiFi EAP PWD Client Takeover Audit"
    meta_cve_id = "CVE-2019-9499"
    meta_severity = "High"
    meta_protocol = "wifi"
    meta_target_os = ["all"]
    meta_required_params = ["wifi_interface"]
    meta_profiles = ["wifi"]
    is_disruptive = True
    meta_destructive_level = "Restart"

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
            "The real flaw can permit session control; this audit sent no EAP-pwd commit."
        )
        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "EAP-PWD client session-takeover exposure audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    params = {"wifi_interface": sys.argv[1]} if len(sys.argv) > 1 else {}
    WiFiEAPPWDClientTakeoverAuditPlugin(params).run_verify()

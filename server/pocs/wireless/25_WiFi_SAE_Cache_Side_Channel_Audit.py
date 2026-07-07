"""
PoC Name: Wi-Fi SAE Cache Side-Channel Audit
CVE: CVE-2022-23303
Category: Wireless
Severity: Critical
Description: Audit vulnerable SAE implementations without collecting cache traces.
Reference: https://nvd.nist.gov/vuln/detail/CVE-2022-23303
"""
from __future__ import annotations

import sys

from iv_plugin_base import IVIVulnerabilityPlugin
from wireless_cve_audit import as_bool, local_version, version_tuple


class WiFiSAECacheSideChannelAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-025"
    meta_poc_name = "WiFi SAE Cache Side Channel Audit"
    meta_cve_id = "CVE-2022-23303"
    meta_severity = "Critical"
    meta_protocol = "wifi"
    meta_target_os = ["android", "linux"]
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
        sae_enabled = as_bool(self.params.get("sae_enabled"))
        parsed = version_tuple(version)
        affected = bool(parsed and parsed < (2, 10, 0))
        vulnerable = bool(affected and sae_enabled is True)
        evidence = (
            f"interface={self.interface}; wpa_supplicant_version={version or 'unknown'}; "
            f"sae_enabled={sae_enabled}; affected_before_2_10={affected}. "
            "No cache trace collection or password recovery was attempted."
        )
        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "SAE cache side-channel exposure audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    params = {"wifi_interface": sys.argv[1]} if len(sys.argv) > 1 else {}
    WiFiSAECacheSideChannelAuditPlugin(params).run_verify()

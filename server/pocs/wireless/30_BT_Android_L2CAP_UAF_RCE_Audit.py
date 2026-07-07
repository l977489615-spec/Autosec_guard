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


class BTAndroidL2CAPUAFRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-030"
    meta_poc_name = "BT Android L2CAP UAF RCE Audit"
    meta_cve_id = "CVE-2021-0475"
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
            "description": "Android L2CAP use-after-free RCE exposure audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    params = {"bluetooth_mac": sys.argv[1]} if len(sys.argv) > 1 else {}
    BTAndroidL2CAPUAFRCEAuditPlugin(params).run_verify()

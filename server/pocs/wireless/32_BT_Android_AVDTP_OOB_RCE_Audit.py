"""
PoC Name: Android Bluetooth AVDTP Out-of-Bounds RCE Audit
CVE: CVE-2022-20411
Category: Wireless
Severity: Critical
Reference: https://nvd.nist.gov/vuln/detail/CVE-2022-20411
"""
from __future__ import annotations

import sys

from iv_plugin_base import IVIVulnerabilityPlugin
from wireless_cve_audit import android_exposure


class BTAndroidAVDTPOOBRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-032"
    meta_poc_name = "BT Android AVDTP OOB RCE Audit"
    meta_cve_id = "CVE-2022-20411"
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
            self.params, {"10", "11", "12", "12.1", "13"}, "2022-12-01"
        )
        evidence = f"target={self.target_mac}; {evidence}"
        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "Android AVDTP out-of-bounds RCE exposure audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    params = {"bluetooth_mac": sys.argv[1]} if len(sys.argv) > 1 else {}
    BTAndroidAVDTPOOBRCEAuditPlugin(params).run_verify()

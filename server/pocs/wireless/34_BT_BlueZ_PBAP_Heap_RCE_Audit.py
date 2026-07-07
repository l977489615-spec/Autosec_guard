"""
PoC Name: BlueZ PBAP Heap Overflow RCE Audit
CVE: CVE-2023-50230
Category: Wireless
Severity: High
Reference: https://nvd.nist.gov/vuln/detail/CVE-2023-50230
"""
from __future__ import annotations

import sys

from iv_plugin_base import IVIVulnerabilityPlugin
from wireless_cve_audit import as_bool, local_version, version_tuple


class BTBlueZPBAPHeapRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-034"
    meta_poc_name = "BT BlueZ PBAP Heap RCE Audit"
    meta_cve_id = "CVE-2023-50230"
    meta_severity = "High"
    meta_protocol = "bluetooth"
    meta_target_os = ["linux"]
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
        version = local_version(self.params.get("bluez_version"), "bluetoothctl", "--version")
        parsed = version_tuple(version)
        affected = bool(parsed and (5, 66, 0) <= parsed < (5, 70, 0))
        pbap_enabled = as_bool(self.params.get("pbap_enabled"))
        vulnerable = bool(affected and pbap_enabled is True)
        evidence = (
            f"target={self.target_mac}; bluez_version={version or 'unknown'}; "
            f"affected_5_66_to_5_69={affected}; pbap_enabled={pbap_enabled}. "
            "The real flaw can yield root-context code execution; no PBAP payload was transmitted."
        )
        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "BlueZ PBAP heap-overflow RCE exposure audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    params = {"bluetooth_mac": sys.argv[1]} if len(sys.argv) > 1 else {}
    BTBlueZPBAPHeapRCEAuditPlugin(params).run_verify()

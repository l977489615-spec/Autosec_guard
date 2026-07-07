"""
PoC Name: Bluetooth KNOB Key-Length Policy Audit
CVE: CVE-2019-9506
Component: Bluetooth BR/EDR key negotiation
Category: Wireless
Severity: High
Description: Audit Bluetooth version and minimum encryption-key policy without downgrading a link.
References:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-9506
Prerequisites: Target Bluetooth MAC and bluetoothctl, or explicit Bluetooth policy parameters.
Usage: python3 22_BT_KNOB_Key_Length_Audit.py <target_mac> [bluetooth_version] [min_key_size]
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys

from iv_plugin_base import IVIVulnerabilityPlugin


def _version_tuple(value: str) -> tuple[int, int] | None:
    match = re.search(r"(\d+)\.(\d+)", value or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


class BTKNOBKeyLengthAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-022"
    meta_poc_name = "BT KNOB Key Length Audit"
    meta_cve_id = "CVE-2019-9506"
    meta_severity = "High"
    meta_protocol = "bluetooth"
    meta_target_os = ["all"]
    meta_required_params = ["bluetooth_mac"]
    meta_profiles = ["bluetooth"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.target_mac = (
            self.params.get("bluetooth_mac")
            or self.params.get("target_mac")
            or self.params.get("bd_addr")
            or ""
        )
        if not self.target_mac:
            raise RuntimeError("需要 bluetooth_mac、target_mac 或 bd_addr")
        return True

    def _device_info(self) -> str:
        if not shutil.which("bluetoothctl"):
            return ""
        result = subprocess.run(
            ["bluetoothctl", "info", self.target_mac],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return (result.stdout or "") + "\n" + (result.stderr or "")

    def exploit(self):
        version_text = str(self.params.get("bluetooth_version") or "").strip()
        version = _version_tuple(version_text)
        min_key_raw = self.params.get("minimum_encryption_key_size")
        try:
            min_key_size = int(min_key_raw) if min_key_raw not in (None, "") else None
        except (TypeError, ValueError):
            min_key_size = None
        patch_state = self.params.get("knob_patched")
        explicitly_patched = patch_state in (True, "true", "True", "1", 1)
        version_exposed = bool(version and version <= (5, 1))
        weak_policy = min_key_size is not None and min_key_size < 7
        vulnerable = bool(not explicitly_patched and version_exposed and weak_policy)
        info = self._device_info().strip().replace("\n", "; ")

        evidence = (
            f"target={self.target_mac}; bluetooth_version={version_text or 'unknown'}; "
            f"minimum_encryption_key_size={min_key_size if min_key_size is not None else 'unknown'}; "
            f"version_at_risk={version_exposed}; patch_declared={explicitly_patched}; "
            f"bluetoothctl_info={info or 'unavailable'}. "
            "No key-length downgrade or traffic decryption was attempted."
        )
        if version_exposed and min_key_size is None:
            evidence += " Version is in the affected specification range, but key policy was not observable."

        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "KNOB minimum BR/EDR encryption-key policy audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 22_BT_KNOB_Key_Length_Audit.py <target_mac> [bluetooth_version] [min_key_size]")
        raise SystemExit(1)
    params = {"bluetooth_mac": sys.argv[1]}
    if len(sys.argv) > 2:
        params["bluetooth_version"] = sys.argv[2]
    if len(sys.argv) > 3:
        params["minimum_encryption_key_size"] = sys.argv[3]
    BTKNOBKeyLengthAuditPlugin(params).run_verify()

"""
PoC Name: Bluetooth BLURtooth CTKD Policy Audit
CVE: CVE-2020-15802
Component: Bluetooth Cross-Transport Key Derivation
Category: Wireless
Severity: High
Description: Audit dual-mode CTKD exposure without replacing an existing bond.
References:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-15802
  - https://www.kb.cert.org/vuls/id/589825
Prerequisites: Target Bluetooth MAC and explicit version/CTKD evidence where available.
Usage: python3 23_BT_BLURtooth_CTKD_Audit.py <target_mac> [bluetooth_version] [ctkd_enabled]
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


def _as_bool(value):
    if value in (True, "true", "True", "1", 1, "yes", "enabled"):
        return True
    if value in (False, "false", "False", "0", 0, "no", "disabled"):
        return False
    return None


class BTBLURtoothCTKDAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-023"
    meta_poc_name = "BT BLURtooth CTKD Audit"
    meta_cve_id = "CVE-2020-15802"
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
        ctkd_enabled = _as_bool(self.params.get("ctkd_enabled"))
        patch_state = _as_bool(self.params.get("blurtooth_patched"))
        affected_spec = bool(version and version < (5, 1))
        vulnerable = bool(affected_spec and ctkd_enabled is True and patch_state is not True)
        info = self._device_info().strip().replace("\n", "; ")

        evidence = (
            f"target={self.target_mac}; bluetooth_version={version_text or 'unknown'}; "
            f"ctkd_enabled={ctkd_enabled if ctkd_enabled is not None else 'unknown'}; "
            f"affected_spec={affected_spec}; patch_declared={patch_state is True}; "
            f"bluetoothctl_info={info or 'unavailable'}. "
            "No pairing, bond replacement, or key overwrite was attempted."
        )
        if affected_spec and ctkd_enabled is None:
            evidence += " The specification version is potentially affected, but CTKD state was not observable."

        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "BLURtooth cross-transport key-derivation policy audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 23_BT_BLURtooth_CTKD_Audit.py <target_mac> [bluetooth_version] [ctkd_enabled]")
        raise SystemExit(1)
    params = {"bluetooth_mac": sys.argv[1]}
    if len(sys.argv) > 2:
        params["bluetooth_version"] = sys.argv[2]
    if len(sys.argv) > 3:
        params["ctkd_enabled"] = sys.argv[3]
    BTBLURtoothCTKDAuditPlugin(params).run_verify()

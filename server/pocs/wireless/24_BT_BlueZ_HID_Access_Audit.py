"""
PoC Name: BlueZ HID Authorization Configuration Audit
CVE: CVE-2023-45866, CVE-2024-8805
Component: BlueZ HID/HOG authorization
Category: Wireless
Severity: High
Description: Audit BlueZ version and input policy without pairing or injecting HID reports.
References:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-45866
  - https://nvd.nist.gov/vuln/detail/CVE-2024-8805
Prerequisites: Target Bluetooth MAC plus BlueZ version/config evidence.
Usage: python3 24_BT_BlueZ_HID_Access_Audit.py <target_mac> [bluez_version] [input_conf]
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

from iv_plugin_base import IVIVulnerabilityPlugin


def _version_tuple(value: str) -> tuple[int, int] | None:
    match = re.search(r"(\d+)\.(\d+)", value or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


class BTBlueZHIDAccessAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-024"
    meta_poc_name = "BT BlueZ HID Access Audit"
    meta_cve_id = "CVE-2023-45866,CVE-2024-8805"
    meta_severity = "High"
    meta_protocol = "bluetooth"
    meta_target_os = ["linux"]
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

    def _run(self, command: list[str]) -> str:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return ((result.stdout or "") + "\n" + (result.stderr or "")).strip()

    def _bluez_version(self) -> str:
        explicit = str(self.params.get("bluez_version") or "").strip()
        if explicit:
            return explicit
        if shutil.which("bluetoothctl"):
            return self._run(["bluetoothctl", "--version"])
        return ""

    def _input_config(self) -> tuple[str, str]:
        explicit = str(self.params.get("bluez_input_config") or "").strip()
        candidates = [Path(explicit)] if explicit else []
        candidates.extend([
            Path("/etc/bluetooth/input.conf"),
            Path("/etc/bluetooth/main.conf"),
        ])
        for path in candidates:
            if path.is_file():
                return path.read_text(encoding="utf-8", errors="replace"), str(path)
        return "", "unavailable"

    def exploit(self):
        version_text = self._bluez_version()
        version = _version_tuple(version_text)
        config, config_source = self._input_config()
        normalized = config.lower()
        classic_bonded_only_false = bool(
            re.search(r"^\s*classicbondedonly\s*=\s*false", normalized, re.MULTILINE)
        )
        userspace_hid_true = bool(
            re.search(r"^\s*userspacehid\s*=\s*true", normalized, re.MULTILINE)
        )
        affected_2024 = version == (5, 77)
        policy_exposed = classic_bonded_only_false or userspace_hid_true
        vulnerable = bool(affected_2024 or policy_exposed)
        device_info = (
            self._run(["bluetoothctl", "info", self.target_mac])
            if shutil.which("bluetoothctl")
            else ""
        )

        evidence = (
            f"target={self.target_mac}; bluez_version={version_text or 'unknown'}; "
            f"config_source={config_source}; "
            f"classic_bonded_only_false={classic_bonded_only_false}; "
            f"userspace_hid_true={userspace_hid_true}; affected_bluez_5_77={affected_2024}; "
            f"device_info={device_info.replace(chr(10), '; ') or 'unavailable'}. "
            "No pairing request or HID report was transmitted."
        )
        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "BlueZ HID authorization/version audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 24_BT_BlueZ_HID_Access_Audit.py <target_mac> [bluez_version] [input_conf]")
        raise SystemExit(1)
    params = {"bluetooth_mac": sys.argv[1]}
    if len(sys.argv) > 2:
        params["bluez_version"] = sys.argv[2]
    if len(sys.argv) > 3:
        params["bluez_input_config"] = sys.argv[3]
    BTBlueZHIDAccessAuditPlugin(params).run_verify()

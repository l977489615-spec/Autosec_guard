#!/usr/bin/env python3
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
Usage: python3 24_CVE_2023_45866_BT_BlueZ_HID_Access_Active_Validation.py <target_mac> [bluez_version] [input_conf]
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


VULN = {
    "id":             0,
    "cve":            "CVE-2023-45866,CVE-2024-8805",
    "year":           2023,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "BT BlueZ HID Access Audit",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2023-45866",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2023-45866"],
    "signature_tokens": ["CVE-2023-45866,CVE-2024-8805"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2023-45866,CVE-2024-8805 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2023-45866,CVE-2024-8805") if vuln else "CVE-2023-45866,CVE-2024-8805",
        "target":    getattr(plugin, "target_ip", "unknown"),
        "technique": "legacy exploit() wrapper",
        "raw":       str(result)[:300],
    }

    # 根据是否有主动网络调用推断等级
    level = "B" if vulnerable is True else ("C" if vulnerable is False else "D")
    try:
        from probe_utils import detection_confidence as _detection_confidence
        return _detection_confidence(level, evidence, vulnerable=vulnerable)
    except ImportError:
        return {
            "detection_confidence": {
                "level": level, "vulnerable": vulnerable,
                "evidence": evidence, "method": "legacy_wrapper",
            }
        }


class BTBlueZHIDAccessAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-024"
    meta_poc_name = 'CVE-2023-45866 BT BlueZ HID Access Active Validation'
    meta_cve_id = "CVE-2023-45866,CVE-2024-8805"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2023-45866"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2023-45866', 'https://nvd.nist.gov/vuln/detail/CVE-2024-8805']
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
        print("Usage: python3 24_CVE_2023_45866_BT_BlueZ_HID_Access_Active_Validation.py <target_mac> [bluez_version] [input_conf]")
        raise SystemExit(1)
    params = {"bluetooth_mac": sys.argv[1]}
    if len(sys.argv) > 2:
        params["bluez_version"] = sys.argv[2]
    if len(sys.argv) > 3:
        params["bluez_input_config"] = sys.argv[3]
    BTBlueZHIDAccessAuditPlugin(params).run_verify()

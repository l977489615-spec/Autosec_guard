"""
PoC Name: Wi-Fi PEAP Authentication Bypass Configuration Audit
CVE: CVE-2023-52160
Component: wpa_supplicant PEAP
Category: Wireless
Severity: High
Description: Audit PEAP certificate and phase-2 settings without creating a rogue AP.
References:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-52160
Prerequisites: Wi-Fi interface plus wpa_cli access or a readable wpa_supplicant config.
Usage: python3 19_WiFi_PEAP_Auth_Bypass_Audit.py <interface> [config_path]
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

from iv_plugin_base import IVIVulnerabilityPlugin


def _version_tuple(value: str) -> tuple[int, ...]:
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", value or "")
    if not match:
        return ()
    return tuple(int(part or 0) for part in match.groups())


class WiFiPEAPAuthBypassAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-019"
    meta_poc_name = "WiFi PEAP Auth Bypass Audit"
    meta_cve_id = "CVE-2023-52160"
    meta_severity = "High"
    meta_protocol = "wifi"
    meta_target_os = ["android", "linux", "chromeos"]
    meta_required_params = ["wifi_interface"]
    meta_profiles = ["wifi"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.interface = (
            self.params.get("wifi_interface")
            or self.params.get("interface")
            or ""
        )
        self.config_path = str(self.params.get("wpa_config_path") or "").strip()
        if not self.interface:
            raise RuntimeError("需要 wifi_interface 或 interface")
        if self.config_path and Path(self.config_path).is_file():
            return True
        if shutil.which("wpa_cli"):
            return True
        raise RuntimeError("需要可读的 wpa_config_path 或 wpa_cli")

    def _run(self, command: list[str]) -> str:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return (result.stdout or "") + "\n" + (result.stderr or "")

    def _supplicant_version(self) -> str:
        explicit = str(self.params.get("wpa_supplicant_version") or "").strip()
        if explicit:
            return explicit
        tool = shutil.which("wpa_supplicant")
        return self._run([tool, "-v"]).strip() if tool else ""

    def _config_text(self) -> str:
        if self.config_path:
            return Path(self.config_path).read_text(encoding="utf-8", errors="replace")

        output = self._run(["wpa_cli", "-i", self.interface, "list_networks"])
        network_ids = []
        for line in output.splitlines():
            first = line.split("\t", 1)[0].strip()
            if first.isdigit():
                network_ids.append(first)

        blocks = []
        for network_id in network_ids:
            values = {}
            for key in ("ssid", "key_mgmt", "eap", "ca_cert", "phase2"):
                values[key] = self._run(
                    ["wpa_cli", "-i", self.interface, "get_network", network_id, key]
                ).strip()
            blocks.append("\n".join(f"{key}={value}" for key, value in values.items()))
        return "\n\n".join(blocks)

    def exploit(self):
        version = self._supplicant_version()
        config = self._config_text()
        normalized = config.lower()
        uses_peap = bool(re.search(r"\beap\s*=\s*[\"']?peap", normalized))
        has_ca_cert = bool(
            re.search(r"\bca_cert\s*=\s*[\"']?(?!none|null|$).+", normalized)
        )
        has_phase2 = bool(
            re.search(r"\bphase2\s*=\s*[\"']?.*(auth|autheap)=", normalized)
        )
        parsed_version = _version_tuple(version)
        affected_version = bool(parsed_version and parsed_version <= (2, 10, 0))
        unsafe_config = uses_peap and (not has_ca_cert or not has_phase2)

        vulnerable = unsafe_config and (affected_version or not parsed_version)
        evidence = (
            f"interface={self.interface}; wpa_supplicant_version={version or 'unknown'}; "
            f"peap={uses_peap}; ca_cert_configured={has_ca_cert}; "
            f"phase2_configured={has_phase2}; affected_version={affected_version}. "
            "This is a configuration/version audit; no rogue access point was created."
        )
        if unsafe_config and not parsed_version:
            evidence += " Version is unknown, so the finding is a potential exposure."

        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "PEAP authentication-bypass prerequisite audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 19_WiFi_PEAP_Auth_Bypass_Audit.py <interface> [config_path]")
        raise SystemExit(1)
    params = {"wifi_interface": sys.argv[1]}
    if len(sys.argv) > 2:
        params["wpa_config_path"] = sys.argv[2]
    WiFiPEAPAuthBypassAuditPlugin(params).run_verify()

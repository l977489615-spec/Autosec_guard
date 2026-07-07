"""
PoC Name: Wi-Fi FragAttacks Kernel Exposure Audit
CVE: CVE-2020-24586, CVE-2020-24587, CVE-2020-24588
Component: IEEE 802.11 fragmentation and aggregation handling
Category: Wireless
Severity: High
Description: Compare the target Linux kernel branch with documented FragAttacks fixes.
References:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-24586
  - https://nvd.nist.gov/vuln/detail/CVE-2020-24587
  - https://nvd.nist.gov/vuln/detail/CVE-2020-24588
Prerequisites: Wi-Fi interface and target_kernel_version, ADB, or local uname access.
Usage: python3 20_WiFi_FragAttacks_Kernel_Audit.py <interface> [kernel_version]
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys

from iv_plugin_base import IVIVulnerabilityPlugin


PATCH_LEVELS = {
    (4, 4): (4, 4, 271),
    (4, 9): (4, 9, 271),
    (4, 14): (4, 14, 235),
    (4, 19): (4, 19, 193),
    (5, 4): (5, 4, 124),
    (5, 10): (5, 10, 42),
    (5, 12): (5, 12, 9),
}


def _kernel_tuple(value: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", value or "")
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


class WiFiFragAttacksKernelAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-020"
    meta_poc_name = "WiFi FragAttacks Kernel Audit"
    meta_cve_id = "CVE-2020-24586,CVE-2020-24587,CVE-2020-24588"
    meta_severity = "High"
    meta_protocol = "wifi"
    meta_target_os = ["android", "linux"]
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
        if not self.interface:
            raise RuntimeError("需要 wifi_interface 或 interface")
        return True

    def _run(self, command: list[str]) -> str:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return (result.stdout or "").strip()

    def _target_kernel(self) -> tuple[str, str]:
        explicit = str(self.params.get("target_kernel_version") or "").strip()
        if explicit:
            return explicit, "parameter"

        serial = str(
            self.params.get("expected_usb_serial")
            or self.params.get("usb_device_serial")
            or ""
        ).strip()
        if serial and shutil.which("adb"):
            value = self._run(["adb", "-s", serial, "shell", "uname", "-r"])
            if value:
                return value, "adb"

        return self._run(["uname", "-r"]), "local_uname"

    def _driver_info(self) -> str:
        if not shutil.which("ethtool"):
            return ""
        return self._run(["ethtool", "-i", self.interface])

    def exploit(self):
        kernel_text, source = self._target_kernel()
        kernel = _kernel_tuple(kernel_text)
        branch = kernel[:2] if kernel else None
        fixed_at = PATCH_LEVELS.get(branch) if branch else None
        vulnerable = bool(kernel and fixed_at and kernel < fixed_at)
        patched_or_unlisted = bool(kernel and (not fixed_at or kernel >= fixed_at))
        driver = self._driver_info().replace("\n", "; ")

        evidence = (
            f"interface={self.interface}; kernel={kernel_text or 'unknown'}; "
            f"kernel_source={source}; fixed_at={fixed_at or 'branch-not-listed'}; "
            f"driver={driver or 'unknown'}. "
            "Version matching is conservative and may not detect vendor backports."
        )
        if not kernel:
            evidence += " Kernel version could not be parsed; exposure was not confirmed."
        elif patched_or_unlisted:
            evidence += " The observed kernel is at/above the listed fix or outside the listed branches."

        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "FragAttacks affected-kernel branch audit",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 20_WiFi_FragAttacks_Kernel_Audit.py <interface> [kernel_version]")
        raise SystemExit(1)
    params = {"wifi_interface": sys.argv[1]}
    if len(sys.argv) > 2:
        params["target_kernel_version"] = sys.argv[2]
    WiFiFragAttacksKernelAuditPlugin(params).run_verify()

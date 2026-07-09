#!/usr/bin/env python3
"""
PoC Name: Broadcom Wi-Fi Firmware RCE Active Validation
CVE: CVE-2017-0561
Category: Wireless
Severity: Critical
Description: Identify the affected Android kernel/chipset combination without sending firmware payloads.
Reference: https://nvd.nist.gov/vuln/detail/CVE-2017-0561
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys

from iv_plugin_base import IVIVulnerabilityPlugin
from wireless_cve_audit import as_bool


AFFECTED_ANDROID_RELEASES = {"6", "6.0", "6.0.1", "7", "7.0", "7.1", "7.1.1", "7.1.2"}
BROADCOM_MARKERS = ("broadcom", "brcm", "bcm43", "bcm434", "bcm435", "bcm436")
FIXED_SECURITY_BULLETIN = "2017-07-05"


VULN = {
    "id":             0,
    "cve":            "CVE-2017-0561",
    "year":           2017,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "WiFi Broadcom Firmware RCE Audit",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2017-0561",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2017-0561"],
    "signature_tokens": ["CVE-2017-0561"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2017-0561 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2017-0561") if vuln else "CVE-2017-0561",
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


class WiFiBroadcomFirmwareRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-026"
    meta_poc_name = 'CVE-2017-0561 WiFi Broadcom Firmware RCE Active Validation'
    meta_cve_id = "CVE-2017-0561"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2017-0561"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2017-0561']
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
        self.serial = str(
            self.params.get("expected_usb_serial")
            or self.params.get("usb_device_serial")
            or self.params.get("serial")
            or ""
        ).strip()
        return True

    def _run(self, command: list[str]) -> str:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return (result.stdout or result.stderr or "").strip()

    def _adb_shell(self, *args: str) -> str:
        if not self.serial or not shutil.which("adb"):
            return ""
        try:
            return self._run(["adb", "-s", self.serial, "shell", *args])
        except Exception:
            return ""

    def _local_kernel(self) -> tuple[str, str]:
        explicit = str(self.params.get("target_kernel_version") or "").strip()
        if explicit:
            return explicit, "parameter"
        if self.serial:
            value = self._adb_shell("uname", "-r")
            if value:
                return value, "adb:uname"
        return self._run(["uname", "-r"]), "local_uname"

    def _android_release(self) -> tuple[str, str]:
        explicit = str(self.params.get("android_version") or "").strip()
        if explicit:
            return explicit, "parameter"
        if self.serial:
            value = self._adb_shell("getprop", "ro.build.version.release")
            if value:
                return value, "adb:getprop"
        return "", "unknown"

    def _security_patch(self) -> tuple[str, str]:
        explicit = str(self.params.get("android_security_patch") or "").strip()
        if explicit:
            return explicit, "parameter"
        if self.serial:
            value = self._adb_shell("getprop", "ro.build.version.security_patch")
            if value:
                return value, "adb:getprop"
        return "", "unknown"

    def _chipset_inventory(self) -> tuple[str, str]:
        explicit = str(self.params.get("wifi_chipset") or "").strip()
        if explicit:
            return explicit, "parameter"

        probe_payload = ["ethtool", "-i", self.interface]
        if self.serial:
            payload = ["dumpsys", "wifi"]
            wifi_dump = self._adb_shell(*payload)
            if wifi_dump:
                return wifi_dump, "adb:dumpsys wifi"
            for prop in ("ro.hardware.wlan", "vendor.wlan.driver.status", "ro.boot.hardware", "ro.hardware"):
                prop_value = self._adb_shell("getprop", prop)
                if prop_value:
                    return f"{prop}={prop_value}", f"adb:getprop:{prop}"

        if shutil.which("ethtool"):
            text = self._run(probe_payload)
            if text:
                return text, "local:ethtool"

        if shutil.which("iw"):
            payload = ["iw", "dev", self.interface, "info"]
            text = self._run(payload)
            if text:
                return text, "local:iw"
        return "", "unknown"

    def _android_release_key(self, release: str) -> str:
        match = re.search(r"(\d+(?:\.\d+)?)", release or "")
        return match.group(1) if match else ""

    def exploit(self):
        kernel, kernel_source = self._local_kernel()
        android_release, release_source = self._android_release()
        security_patch, patch_source = self._security_patch()
        chipset_text, chipset_source = self._chipset_inventory()
        patched = as_bool(self.params.get("cve_2017_0561_patched"))
        affected_kernel = kernel.startswith(("3.10", "3.18"))
        release_key = self._android_release_key(android_release)
        affected_android = release_key in AFFECTED_ANDROID_RELEASES
        lowered_chipset = chipset_text.lower()
        broadcom = any(token in lowered_chipset for token in BROADCOM_MARKERS)
        patch_missing = patched is False or (
            bool(re.match(r"\d{4}-\d{2}-\d{2}$", security_patch or ""))
            and security_patch < FIXED_SECURITY_BULLETIN
        )
        vulnerable = bool(broadcom and (affected_kernel or affected_android) and patch_missing)
        chipset_excerpt = " ".join(chipset_text.split())[:220]
        evidence = (
            f"interface={self.interface}; serial={self.serial or 'none'}; "
            f"kernel={kernel or 'unknown'}; kernel_source={kernel_source}; affected_kernel={affected_kernel}; "
            f"android_release={android_release or 'unknown'}; release_source={release_source}; "
            f"affected_android={affected_android}; android_release_key={release_key or 'unknown'}; "
            f"security_patch={security_patch or 'unknown'}; patch_source={patch_source}; "
            f"fixed_bulletin={FIXED_SECURITY_BULLETIN}; patch_declared={patched}; patch_missing={patch_missing}; "
            f"chipset_source={chipset_source}; broadcom_family={broadcom}; "
            f"chipset_excerpt={chipset_excerpt or 'unknown'!r}. "
            "This plugin actively queried kernel/build/Wi-Fi inventory via adb/getprop/dumpsys or local driver tooling "
            "to confirm whether the target matches the Broadcom affected family before any lab firmware-trigger step."
        )
        if not chipset_text:
            evidence += " Wi-Fi chipset evidence was not observed; exposure could not be fully confirmed."
        self.results.update({
            "vulnerable": vulnerable,
            "cve_id": self.meta_cve_id,
            "description": "Broadcom Wi-Fi firmware RCE inventory and active environment validation",
            "evidence": evidence,
        })
        return self.results


if __name__ == "__main__":
    params = {"wifi_interface": sys.argv[1]} if len(sys.argv) > 1 else {}
    WiFiBroadcomFirmwareRCEAuditPlugin(params).run_verify()

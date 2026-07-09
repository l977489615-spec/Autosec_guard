#!/usr/bin/env python3
"""
PoC Name  : 检测设备app是否允许不安全的应用数据备份和还原...
CVE       : CWE-530
Category  : application
Severity  : Medium
Type      : Type-A
Description: 检测设备app是否允许不安全的应用数据备份和还原... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 17_CWE_530_Android_AllowBackup_Active_Validation.py <target_ip>
"""

from __future__ import annotations

import argparse
import logging
import re
import sys

from _experiment.apk_manifest import check_manifest, run_apk_manifest_check

POC_TAG = "12. 检测设备app是否允许不安全的应用数据备份和还原..."
PATTERN = re.compile(r'\b(?:android:)?allowBackup\s*=\s*"true"', re.IGNORECASE)


def run_check() -> bool:
    parser = argparse.ArgumentParser(description="检测 allowBackup=true")
    parser.add_argument("--serial", help="ADB serial")
    args = parser.parse_args()

    vulnerable, message = run_apk_manifest_check(
        device_serial=args.serial,
        vulnerable_if=lambda path: check_manifest(path, PATTERN),
    )
    logging.warning(message)
    return vulnerable


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable



import sys as _sys_adb
from pathlib import Path as _Path_adb
_sys_adb.path.insert(0, str(_Path_adb(__file__).parent))
try:
    from probe_utils import ADBProbe, detection_confidence
    _PROBE_UTILS_AVAILABLE = True
except ImportError:
    ADBProbe = None  # type: ignore
    detection_confidence = None  # type: ignore
    _PROBE_UTILS_AVAILABLE = False

try:
    from active_validation_core import run_active_validation as _run_active_validation
    _ACTIVE_VALIDATION_AVAILABLE = True
except ImportError:
    _run_active_validation = None  # type: ignore
    _ACTIVE_VALIDATION_AVAILABLE = False

VULN = {
    'cve': 'CWE-530',
    'year': 530,
    'source_url': 'https://cwe.mitre.org/data/definitions/530.html',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    "id": 'CWE-530',
    "domain": "application",
    "vendor_product": "Android IVI Application",
    "component": 'allowbackup',
    "type": 'configuration',
    "summary": 'allowBackup=true 应用数据备份风险检测',
    "requires_manual_review": True,
}


def _run_poc(plugin, vuln=None) -> dict:
    params = plugin.params or {}
    bt_serial = (
        params.get("adb_serial")
        or params.get("android_serial")
        or params.get("expected_usb_serial")
    )
    package = params.get("package") or params.get("android_package") or ""

    evidence: dict = {
        "check_type": 'android_allow_backup',
        "technique": "ADB device interrogation + static analysis fallback",
    }

    if _PROBE_UTILS_AVAILABLE and ADBProbe is not None:
        try:
            adb = ADBProbe(serial=bt_serial)
            if adb.available():
                devices = adb.devices()
                evidence["adb_devices"] = [d["serial"] for d in devices]
                if devices:
                    if not bt_serial:
                        adb.serial = devices[0]["serial"]
                    device_info = adb.device_info()
                    evidence.update(device_info)
                    evidence["adb_connected"] = True
                    # ADB: check app allowBackup setting
                    allow_backup = adb.check_app_allowbackup(package) if package else None
                    pkg_info = adb.package_info(package) if package else ""
                    evidence["allow_backup_result"] = allow_backup
                    evidence["pkg_flags_snippet"] = pkg_info[:500] if pkg_info else ""
                    vulnerable = allow_backup
                    conf = detection_confidence("C", evidence, "adb_device_probe") if detection_confidence else {"level": "C"}
                    return {
                        "vulnerable": vulnerable,
                        "evidence": evidence,
                        "detection_confidence": conf,
                        "requires_manual_review": vulnerable is None,
                    }
        except Exception as _exc:
            evidence["adb_probe_error"] = str(_exc)

    evidence["adb_connected"] = False
    try:
        static_result = run_check()
    except SystemExit:
        static_result = None
    except Exception as _e:
        static_result = None
        evidence["static_analysis_error"] = str(_e)

    evidence["static_analysis_result"] = static_result
    conf = detection_confidence("D", evidence, "static_manifest_analysis") if detection_confidence else {"level": "D"}
    return {
        "vulnerable": static_result,
        "evidence": evidence,
        "detection_confidence": conf,
        "requires_manual_review": True,
    }

class Poc12AllowbackupPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-017"
    meta_poc_name = 'CWE-530 Android AllowBackup Active Validation'
    meta_cve_id = 'CWE-530'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/530.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/530.html']
    meta_severity = 'Medium'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['application']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        if _ACTIVE_VALIDATION_AVAILABLE and _run_active_validation is not None:
            return _run_active_validation(self, VULN, probe=_run_poc)
        return execute_check_callable(run_check, self)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "17_Android_AllowBackup_Audit") if "VULN" in dir() else "17_Android_AllowBackup_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc12AllowbackupPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

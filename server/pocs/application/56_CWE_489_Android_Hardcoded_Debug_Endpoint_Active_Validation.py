#!/usr/bin/env python3
"""Static template for hardcoded debug or staging endpoints."""
from __future__ import annotations

import os
import re

POC_TAG = "131. 硬编码调试接口与测试域名检测"


def run_check() -> bool:
    text = os.environ.get("AUTOSEC_ANDROID_SOURCE_TEXT", "")
    fixture = os.environ.get("AUTOSEC_ANDROID_SOURCE_FIXTURE", "")
    if fixture and os.path.isfile(fixture):
        text = open(fixture, "r", encoding="utf-8", errors="ignore").read()
    pattern = r"https?://[^\"'\s]*(debug|dev|test|staging|mock|internal)[^\"'\s]*"
    hits = re.findall(pattern, text, re.I)
    print("[RESULT] hardcoded debug endpoint count:", len(hits))
    return bool(hits)


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
    'cve': 'CWE-489',
    'year': 489,
    'source_url': 'https://cwe.mitre.org/data/definitions/489.html',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    "id": 'CWE-489',
    "domain": "application",
    "vendor_product": "Android IVI Application",
    "component": 'hardcoded_debug_endpoint',
    "type": 'information_disclosure',
    "summary": '硬编码调试接口与测试域名检测',
    "requires_manual_review": True,
}


def _run_poc(plugin, vuln=None) -> dict:
    """ADB-integrated probe: Grade C when device connected, Grade D fallback."""
    params = plugin.params or {}
    bt_serial = (
        params.get("adb_serial")
        or params.get("android_serial")
        or params.get("expected_usb_serial")
    )
    package = params.get("package") or params.get("android_package") or ""

    evidence: dict = {
        "check_type": 'android_hardcoded_debug_endpoint',
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
                    # ADB: check logcat and network traffic for debug endpoint patterns
                    log_out = adb.shell(
                        "logcat -d -v brief -t 200 2>/dev/null | "
                        "grep -iE 'debug|dev|test|staging|mock|internal' | grep -i 'http' | head -10"
                    )
                    evidence["debug_endpoint_log_matches"] = log_out
                    vulnerable = bool(log_out) if log_out else None
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

class Poc131HardcodedDebugEndpointPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-056"
    meta_poc_name = 'CWE-489 Android 硬编码调试端点 Active Validation'
    meta_cve_id = 'CWE-489'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/489.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/489.html']
    meta_severity = 'Medium'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['android_source_fixture']
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

    _desc = VULN.get("summary", "56_Android_Hardcoded_Debug_Endpoint_Audit") if "VULN" in dir() else "56_Android_Hardcoded_Debug_Endpoint_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc131HardcodedDebugEndpointPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

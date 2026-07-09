#!/usr/bin/env python3
"""Manifest template for exported Provider or permissive grantUriPermissions."""
from __future__ import annotations

import os
import re

POC_TAG = "129. Provider 导出与 grantUriPermissions 风险检测"


def run_check() -> bool:
    manifest = os.environ.get("AUTOSEC_ANDROID_MANIFEST_TEXT", "")
    path = os.environ.get("AUTOSEC_ANDROID_MANIFEST", "")
    if path and os.path.isfile(path):
        manifest = open(path, "r", encoding="utf-8", errors="ignore").read()
    providers = re.findall(r"<provider\b[^>]*>", manifest, re.I)
    hit = any("exported=\"true\"" in item or "granturipermissions=\"true\"" in item.lower() for item in providers)
    print("[RESULT] provider exposure pattern:", "FOUND" if hit else "not found")
    return hit


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
    'cve': 'CWE-926',
    'year': 926,
    'source_url': 'https://cwe.mitre.org/data/definitions/926.html',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    "id": 'CWE-926',
    "domain": "application",
    "vendor_product": "Android IVI Application",
    "component": 'provider_uri_grant',
    "type": 'security_misconfiguration',
    "summary": 'Provider 导出与 grantUriPermissions 风险检测',
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
        "check_type": 'android_provider_uri_grant',
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
                    # ADB: check content providers and grantUriPermissions
                    provider_info = adb.shell(
                        f"content query --uri content://{package}/ 2>/dev/null | head -5"
                        if package else ""
                    )
                    pkg_info = adb.package_info(package) if package else ""
                    has_grant_uri = "grantUriPermissions=true" in pkg_info or "GRANT_URI" in pkg_info
                    evidence["provider_query_result"] = provider_info
                    evidence["has_grant_uri_permissions"] = has_grant_uri
                    vulnerable = has_grant_uri or bool(provider_info) if (has_grant_uri or provider_info) else None
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

class Poc129ProviderGrantUriPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-054"
    meta_poc_name = 'CWE-926 Android Provider URI授权 Active Validation'
    meta_cve_id = 'CWE-926'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/926.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/926.html']
    meta_severity = 'High'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['android_manifest']
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

    _desc = VULN.get("summary", "54_Android_Provider_URI_Grant_Audit") if "VULN" in dir() else "54_Android_Provider_URI_Grant_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc129ProviderGrantUriPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

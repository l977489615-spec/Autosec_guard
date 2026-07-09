#!/usr/bin/env python3
"""
PoC Name  : 检测设备app是否存在不安全的ContentProvider导出（存在暴露风险）...
CVE       : CWE-926
Category  : application
Severity  : High
Type      : Type-A
Description: 检测设备app是否存在不安全的ContentProvider导出（存在暴露风险）... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 22_CWE_926_Android_Exported_Provider_Active_Validation.py <target_ip>
"""

from __future__ import annotations

POC_TAG = "17. 检测设备app是否存在不安全的ContentProvider导出（存在暴露风险）..."

from typing import List, Tuple, Optional
import os
import glob
import re
import logging
import xml.etree.ElementTree as ET

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

MANIFEST_PATTERNS = [
    "*_AndroidManifest.xml",
    "*_AndroidManifest_text.txt",
    "*_AndroidManifest_strings.txt",
    "AndroidManifest.xml",
    "AndroidManifest_text.txt",
    "AndroidManifest_strings.txt"
]

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Fallback regexes
RE_PROVIDER_BLOCK = re.compile(r'<\s*provider\b([^>]*)>', flags=re.IGNORECASE | re.DOTALL)
RE_EXPORTED_ATTR = re.compile(r'\b(?:android:)?exported\s*=\s*"(true|false)"', flags=re.IGNORECASE)
RE_NAME_ATTR = re.compile(r'\b(?:android:)?name\s*=\s*"([^"]+)"', flags=re.IGNORECASE)
RE_TARGET_SDK = re.compile(r'<\s*uses-sdk\b[^>]*android:targetSdkVersion\s*=\s*"(\d+)"', flags=re.IGNORECASE)


def find_manifests(search_dir: str = ".") -> List[str]:
    files = []
    for patt in MANIFEST_PATTERNS:
        for p in glob.glob(os.path.join(search_dir, patt)):
            if os.path.isfile(p):
                files.append(p)
    return sorted(list(dict.fromkeys(files)))


def get_attr_ns(elem: ET.Element, attr_name: str) -> Optional[str]:
    v = elem.get(f"{{{ANDROID_NS}}}{attr_name}")
    if v is None:
        v = elem.get(attr_name)
    return v


def analyze_manifest_xml(path: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        return None, f"xml parse error: {e}"

    results: List[dict] = []

    # 获取 targetSdkVersion，如果无法获取则默认为低版本，存在风险
    targetSdk = 16
    uses_sdk_elem = root.find(".//uses-sdk")
    if uses_sdk_elem is not None:
        t = get_attr_ns(uses_sdk_elem, "targetSdkVersion")
        if t and t.isdigit():
            targetSdk = int(t)

    for elem in root.findall(".//provider"):
        name = get_attr_ns(elem, "name") or elem.get("name") or "<unknown>"
        exported_attr = get_attr_ns(elem, "exported")
        if exported_attr is not None:
            if exported_attr.strip().lower() == "true":
                results.append({"name": name, "reason": 'android:exported="true"'})
        else:
            # exported未设置且 targetSdkVersion <=16视为导出
            if targetSdk <= 16:
                results.append({"name": name, "reason": f"no exported attribute and targetSdkVersion={targetSdk}<=16"})
    return results, None


def analyze_manifest_text(path: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception as e:
        return None, f"read error: {e}"

    # 获取 targetSdkVersion，如果无法获取则默认为16
    t = RE_TARGET_SDK.search(txt)
    targetSdk = int(t.group(1)) if t and t.group(1).isdigit() else 16

    results: List[dict] = []

    for m in RE_PROVIDER_BLOCK.finditer(txt):
        attr_text = m.group(1)
        mname = RE_NAME_ATTR.search(attr_text)
        name = mname.group(1) if mname else "<unknown>"
        mex = RE_EXPORTED_ATTR.search(attr_text)
        if mex:
            val = mex.group(1).lower()
            if val == "true":
                results.append({"name": name, "reason": 'android:exported="true" (text)'})
        else:
            if targetSdk <= 16:
                results.append({"name": name, "reason": f"no exported attribute and targetSdkVersion={targetSdk}<=16 (text)"})
    return results, None


def analyze_file(path: str) -> Tuple[Optional[List[dict]], List[str]]:
    messages: List[str] = []
    xml_res, xml_err = analyze_manifest_xml(path)
    if xml_res is not None:
        messages.append(f"XML parse succeeded for {os.path.basename(path)}")
        return xml_res, messages
    messages.append(f"XML parse failed: {xml_err}; fallback to text analysis")
    text_res, text_err = analyze_manifest_text(path)
    if text_res is None:
        messages.append(f"Text analysis failed: {text_err}")
        return None, messages
    messages.append(f"Text analysis succeeded for {os.path.basename(path)}")
    return text_res, messages


def run_check():
    manifests = find_manifests(".")
    if not manifests:
        logging.warning("no manifest-like files found in current directory")
        return

    logging.warning(f"found {len(manifests)} manifest candidate(s): {manifests}")

    overall = []
    for m in manifests:
        res, msgs = analyze_file(m)
        for msg in msgs:
            logging.warning(f"{os.path.basename(m)}: {msg}")
        if res is None:
            logging.warning(f"{os.path.basename(m)}: analysis inconclusive")
            overall.append((m, None))
            continue
        if not res:
            logging.warning(f"{os.path.basename(m)}: no exported ContentProviders detected")
            overall.append((m, []))
            continue
        logging.warning(f"{os.path.basename(m)}: found {len(res)} exported ContentProvider(s):")
        for r in res:
            logging.warning(f"  - [provider] {r['name']}  reason: {r['reason']}")
        overall.append((m, res))

    logging.warning("scan complete. summary:")
    for m, r in overall:
        bn = os.path.basename(m)
        if r is None:
            logging.warning(f"{bn}: INCONCLUSIVE")
        elif isinstance(r, list) and len(r) == 0:
            logging.warning(f"{bn}: OK (no exported providers)")
        else:
            logging.warning(f"{bn}: VULNERABLE ({len(r)} exported entries)")


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
    "component": 'exported_provider',
    "type": 'security_misconfiguration',
    "summary": '不安全 ContentProvider 导出风险检测',
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
        "check_type": 'android_exported_provider',
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
                    # ADB: check exported providers via package dump
                    prov_out = adb.shell(
                        f"dumpsys package {package} 2>/dev/null | grep -A5 'Provider' | head -40"
                        if package else ""
                    )
                    pkg_info = adb.package_info(package) if package else ""
                    has_exported_prov = "exported=true" in pkg_info.lower() and "provider" in pkg_info.lower()
                    evidence["provider_snippet"] = prov_out
                    evidence["has_exported_provider_indicator"] = has_exported_prov
                    vulnerable = True if has_exported_prov else None
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

class Poc17ProviderExportPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-022"
    meta_poc_name = 'CWE-926 Android Exported Provider Active Validation'
    meta_cve_id = 'CWE-926'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/926.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/926.html']
    meta_severity = 'High'
    meta_protocol = 'android'
    meta_target_os = ['android']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['application']
    meta_attack_surface = '车机APP/应用'
    is_disruptive = False
    meta_destructive_level = 'Probe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        if _ACTIVE_VALIDATION_AVAILABLE and _run_active_validation is not None:
            return _run_active_validation(self, VULN, probe=_run_poc)
        return execute_check_callable(run_check, self)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "22_Android_Exported_Provider_Audit") if "VULN" in dir() else "22_Android_Exported_Provider_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc17ProviderExportPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

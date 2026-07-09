#!/usr/bin/env python3
"""
PoC Name  : 检测设备app是否存在不安全的URL Scheme导出（存在暴露风险）...
CVE       : CWE-939
Category  : application
Severity  : High
Type      : Type-A
Description: 检测设备app是否存在不安全的URL Scheme导出（存在暴露风险）... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 24_CWE_939_Android_Scheme_URL_Export_Active_Validation.py <target_ip>
"""

from __future__ import annotations
POC_TAG = "19. 检测设备app是否存在不安全的URL Scheme导出（存在暴露风险）..."


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

# fallback regexes for text analysis
# find activity or activity-alias start tag and capture until its end tag (non-greedy)
RE_ACTIVITY_BLOCK = re.compile(r'<\s*(activity|activity-alias)\b([^>]*)>(.*?)</\s*\1\s*>', flags=re.IGNORECASE | re.DOTALL)
# self-closing tags (unlikely to contain intent-filter) but include for completeness
RE_ACTIVITY_SELF = re.compile(r'<\s*(activity|activity-alias)\b([^>]*)/?>', flags=re.IGNORECASE | re.DOTALL)
# within a block, find <data ... android:scheme="...">
RE_DATA_SCHEME = re.compile(r'<\s*data\b[^>]*\b(?:android:)?scheme\s*=\s*"([^"]+)"', flags=re.IGNORECASE)


def find_manifests(search_dir: str = ".") -> List[str]:
    found = []
    for patt in MANIFEST_PATTERNS:
        for path in glob.glob(os.path.join(search_dir, patt)):
            if os.path.isfile(path):
                found.append(path)
    return sorted(list(dict.fromkeys(found)))


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

    matches = []

    # find activity and activity-alias elements
    for tag in ("activity", "activity-alias"):
        for elem in root.findall(f".//{tag}"):
            comp_name = get_attr_ns(elem, "name") or elem.get("name") or "<unknown>"
            schemes = []
            intent_filter_count = 0
            # iterate child elements to find intent-filter -> data
            for child in list(elem):
                # child.tag may include namespace
                local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if local != "intent-filter":
                    continue
                intent_filter_count += 1
                # within intent-filter, find data elements (ElementTree)
                for data in list(child):
                    dlocal = data.tag.split("}")[-1] if "}" in data.tag else data.tag
                    if dlocal != "data":
                        continue
                    scheme = get_attr_ns(data, "scheme")
                    if scheme:
                        schemes.append(scheme.strip())
            if schemes:
                matches.append({
                    "component_type": tag,
                    "name": comp_name,
                    "schemes": sorted(list(dict.fromkeys(schemes))),
                    "intent_filter_count": intent_filter_count
                })
    return matches, None


def analyze_manifest_text(path: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception as e:
        return None, f"read error: {e}"

    results = []
    # iterate full blocks
    for m in RE_ACTIVITY_BLOCK.finditer(txt):
        tag = m.group(1)
        attr_text = m.group(2)
        inner = m.group(3)
        # try to find component name in start tag attributes
        mname = re.search(r'\b(?:android:)?name\s*=\s*"([^"]+)"', attr_text, flags=re.IGNORECASE)
        name = mname.group(1) if mname else "<unknown>"
        schemes = [mo.group(1).strip() for mo in RE_DATA_SCHEME.finditer(inner)]
        if schemes:
            results.append({
                "component_type": tag,
                "name": name,
                "schemes": sorted(list(dict.fromkeys(schemes))),
                "intent_filter_count": len(re.findall(r'<\s*intent-filter\b', inner, flags=re.IGNORECASE))
            })
    # also check self-closing tags (rare to have intent-filter/data inside)
    # skip for self-closing as they cannot contain intent-filter
    return results, None


def analyze_file(path: str) -> Tuple[Optional[List[dict]], List[str]]:
    msgs = []
    xml_res, xml_err = analyze_manifest_xml(path)
    if xml_res is not None:
        msgs.append("XML parse succeeded")
        return xml_res, msgs
    msgs.append(f"XML parse failed: {xml_err}; falling back to text analysis")
    text_res, text_err = analyze_manifest_text(path)
    if text_res is None:
        msgs.append(f"text analysis failed: {text_err}")
        return None, msgs
    msgs.append("text analysis succeeded")
    return text_res, msgs


def run_check():
    manifests = find_manifests(".")
    if not manifests:
        logging.warning("no manifest-like files found in current directory using expected naming rules")
        return

    logging.warning(f"found {len(manifests)} manifest candidate(s): {manifests}")

    overall = []
    for m in manifests:
        matches, msgs = analyze_file(m)
        for msg in msgs:
            logging.warning(f"{os.path.basename(m)}: {msg}")
        if matches is None:
            logging.warning(f"{os.path.basename(m)}: analysis inconclusive")
            overall.append((m, None))
            continue
        if not matches:
            logging.warning(f"{os.path.basename(m)}: no intent-scheme data found")
            overall.append((m, []))
            continue
        logging.warning(f"{os.path.basename(m)}: found {len(matches)} component(s) declaring scheme URLs:")
        for it in matches:
            logging.warning(f"  - [{it['component_type']}] {it['name']}  schemes={it['schemes']} intent_filters={it['intent_filter_count']}")
        overall.append((m, matches))

    logging.warning("scan complete. summary:")
    for m, res in overall:
        bn = os.path.basename(m)
        if res is None:
            logging.warning(f"{bn}: INCONCLUSIVE")
            return False
        elif isinstance(res, list) and len(res) == 0:
            logging.warning(f"{bn}: OK (no scheme URLs declared)")
            return False
        else:
            logging.warning(f"{bn}: SCHEMES DECLARED ({len(res)} component(s))")
            return True


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
    'cve': 'CWE-939',
    'year': 939,
    'source_url': 'https://cwe.mitre.org/data/definitions/939.html',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    "id": 'CWE-939',
    "domain": "application",
    "vendor_product": "Android IVI Application",
    "component": 'scheme_url_export',
    "type": 'security_misconfiguration',
    "summary": 'Intent URL Scheme 导出风险检测',
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
        "check_type": 'android_scheme_url',
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
                    # ADB: check for scheme-based intent filters
                    scheme_out = adb.shell(
                        f"dumpsys package {package} 2>/dev/null | grep -iE 'scheme|intent-filter|data://' | head -20"
                        if package else "dumpsys package 2>/dev/null | grep -i 'scheme:' | head -15"
                    )
                    evidence["scheme_filter_snippet"] = scheme_out
                    has_scheme = bool(scheme_out and "scheme:" in scheme_out.lower())
                    vulnerable = True if has_scheme else None
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

class Poc19SchemeurlExportPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-024"
    meta_poc_name = 'CWE-939 Android Scheme URL Export Active Validation'
    meta_cve_id = 'CWE-939'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/939.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/939.html']
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

    _desc = VULN.get("summary", "24_Android_Scheme_URL_Export_Audit") if "VULN" in dir() else "24_Android_Scheme_URL_Export_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc19SchemeurlExportPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""
PoC Name  : 检测设备app是否存在不安全的Activity（及 activity-alias）导出（存在暴露风险）...
CVE       : CWE-926
Category  : application
Severity  : High
Type      : Type-A
Description: 检测设备app是否存在不安全的Activity（及 activity-alias）导出（存在暴露风险）... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 20_CWE_926_Android_Exported_Activity_Active_Validation.py <target_ip>
"""

from __future__ import annotations
POC_TAG = "15. 检测设备app是否存在不安全的Activity（及 activity-alias）导出（存在暴露风险）..."


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

# Text fallback regexes
# match a full activity or activity-alias block (start tag to corresponding end tag) non-greedy
RE_ACTIVITY_BLOCK = re.compile(r'<\s*(activity|activity-alias)\b([^>]*)>(.*?)</\s*\1\s*>', flags=re.IGNORECASE | re.DOTALL)
# match self-closing activity tag e.g. <activity ... />
RE_ACTIVITY_SELF_CLOSING = re.compile(r'<\s*(activity|activity-alias)\b([^>]*)/?>', flags=re.IGNORECASE | re.DOTALL)
RE_EXPORTED_ATTR = re.compile(r'\b(?:android:)?exported\s*=\s*"(true|false)"', flags=re.IGNORECASE)
RE_INTENT_FILTER = re.compile(r'<\s*intent-filter\b', flags=re.IGNORECASE)


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

    # find all activity and activity-alias elements under application
    for tag in ("activity", "activity-alias"):
        for elem in root.findall(f".//{tag}"):
            name = get_attr_ns(elem, "name") or elem.get("name") or "<unknown>"
            exported_attr = get_attr_ns(elem, "exported")
            # check intent-filter children
            has_intent = False
            for child in list(elem):
                # child tag may include namespace; use localname check
                tag_local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if tag_local == "intent-filter":
                    has_intent = True
                    break
            # apply rules
            if exported_attr is not None:
                # explicit exported attribute exists
                if exported_attr.strip().lower() == "true":
                    results.append({"type": tag, "name": name, "reason": "android:exported=\"true\""})
            else:
                # exported not set: exported if intent-filter present
                if has_intent:
                    results.append({"type": tag, "name": name, "reason": "no exported attribute and has intent-filter"})
    return results, None


def analyze_manifest_text(path: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception as e:
        return None, f"read error: {e}"

    results: List[dict] = []

    # First handle full blocks like <activity ...> ... </activity>
    for m in RE_ACTIVITY_BLOCK.finditer(txt):
        tag = m.group(1)
        attr_text = m.group(2)
        inner = m.group(3)
        name = "<unknown>"
        # try to extract android:name
        mname = re.search(r'\b(?:android:)?name\s*=\s*"([^"]+)"', attr_text, flags=re.IGNORECASE)
        if mname:
            name = mname.group(1)
        # check exported attribute
        mex = RE_EXPORTED_ATTR.search(attr_text)
        if mex:
            val = mex.group(1).lower()
            if val == "true":
                results.append({"type": tag, "name": name, "reason": "android:exported=\"true\" (text)"})
                continue
            else:
                # explicitly false -> not exported
                continue
        # no explicit exported attribute: check inner for intent-filter
        if RE_INTENT_FILTER.search(inner):
            results.append({"type": tag, "name": name, "reason": "no exported attribute and has intent-filter (text)"})
            continue

    # Also handle self-closing tags like <activity ... />
    for m in RE_ACTIVITY_SELF_CLOSING.finditer(txt):
        tag = m.group(1)
        attr_text = m.group(2)
        # skip if this block already processed above (cheap dedupe by name)
        mname = re.search(r'\b(?:android:)?name\s*=\s*"([^"]+)"', attr_text, flags=re.IGNORECASE)
        name = mname.group(1) if mname else "<unknown>"
        # if already in results skip
        if any(r["name"] == name and r["type"] == tag for r in results):
            continue
        mex = RE_EXPORTED_ATTR.search(attr_text)
        if mex:
            val = mex.group(1).lower()
            if val == "true":
                results.append({"type": tag, "name": name, "reason": "android:exported=\"true\" (self-closing text)"})
        else:
            # self-closing with no exported cannot have intent-filter inside, so not exported
            pass

    return results, None


def analyze_file(path: str) -> Tuple[Optional[List[dict]], List[str]]:
    messages: List[str] = []
    xml_res, xml_err = analyze_manifest_xml(path)
    if xml_res is not None:
        messages.append(f"XML parse succeeded for {os.path.basename(path)}")
        return xml_res, messages
    messages.append(f"XML parse failed: {xml_err}; will fallback to text analysis")
    text_res, text_err = analyze_manifest_text(path)
    if text_res is None:
        messages.append(f"Text analysis failed: {text_err}")
        return None, messages
    messages.append(f"Text analysis succeeded for {os.path.basename(path)}")
    return text_res, messages


def run_check():
    manifests = []
    for patt in MANIFEST_PATTERNS:
        manifests.extend(glob.glob(patt))
    manifests = sorted(list(dict.fromkeys([m for m in manifests if os.path.isfile(m)])))

    if not manifests:
        logging.warning("no manifest-like files found in current directory using expected naming rules")
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
            logging.warning(f"{os.path.basename(m)}: no exported activities detected")
            overall.append((m, []))
            continue
        # report vulnerable activities
        logging.warning(f"{os.path.basename(m)}: found {len(res)} exported activity(ies):")
        for r in res:
            logging.warning(f"  - [{r['type']}] {r['name']}  reason: {r['reason']}")
        overall.append((m, res))

    # summary
    logging.warning("scan complete. summary:")
    for m, r in overall:
        bn = os.path.basename(m)
        if r is None:
            logging.warning(f"{bn}: INCONCLUSIVE")
            return False
        elif isinstance(r, list) and len(r) == 0:
            logging.warning(f"{bn}: OK (no exported activities)")
            return False
        else:
            logging.warning(f"{bn}: VULNERABLE ({len(r)} exported entries)")
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
    'cve': 'CWE-926',
    'year': 926,
    'source_url': 'https://cwe.mitre.org/data/definitions/926.html',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    "id": 'CWE-926',
    "domain": "application",
    "vendor_product": "Android IVI Application",
    "component": 'exported_activity',
    "type": 'security_misconfiguration',
    "summary": '不安全 Activity 导出风险检测',
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
        "check_type": 'android_exported_activity',
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
                    # ADB: enumerate exported activities
                    exported = adb.exported_activities(package) if package else []
                    raw_resolver = adb.shell(
                        f"dumpsys package {package} 2>/dev/null | grep -A1 'Activity Resolver Table' | head -20"
                        if package else ""
                    )
                    evidence["exported_activities"] = exported
                    evidence["activity_resolver_snippet"] = raw_resolver
                    vulnerable = bool(exported) if exported else None
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

class Poc15ActivityExportPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-020"
    meta_poc_name = 'CWE-926 Android Exported Activity Active Validation'
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

    _desc = VULN.get("summary", "20_Android_Exported_Activity_Audit") if "VULN" in dir() else "20_Android_Exported_Activity_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc15ActivityExportPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

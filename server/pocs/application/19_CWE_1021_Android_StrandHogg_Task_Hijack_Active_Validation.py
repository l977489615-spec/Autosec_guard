#!/usr/bin/env python3
"""
PoC Name  : 检测设备app是否存在StrandHogg/Task Hijacking风险（CWE-1021）...
CVE       : CWE-1021
Category  : application
Severity  : High
Type      : Type-A
Description: 检测设备app是否存在StrandHogg/Task Hijacking风险（CWE-1021）... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 19_CWE_1021_Android_StrandHogg_Task_Hijack_Active_Validation.py <target_ip>
"""

from __future__ import annotations
POC_TAG = "14. 检测设备app是否存在StrandHogg/Task Hijacking风险（CWE-1021）..."


import os
import re
import glob
import logging
import xml.etree.ElementTree as ET
from typing import List, Tuple, Optional

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

MANIFEST_PATTERNS = [
    "*_AndroidManifest.xml",
    "*_AndroidManifest_text.txt",
    "*_AndroidManifest_strings.txt",
    "AndroidManifest.xml",
    "AndroidManifest_text.txt",
    "AndroidManifest_strings.txt"
]

# XML namespace for android attrs
ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Text regex helpers for fallback
# match a single <activity ...> start tag (non-greedy) capturing its attributes content
RE_ACTIVITY_TAG = re.compile(r'<\s*(?:activity|activity-alias)\b([^>]*)>', flags=re.IGNORECASE | re.DOTALL)
# within attributes text, extract taskAffinity value
RE_TASK_AFF = re.compile(r'\b(?:android:)?taskAffinity\s*=\s*"([^"]+)"', flags=re.IGNORECASE)
# within attributes text, extract launchMode value
RE_LAUNCH = re.compile(r'\b(?:android:)?launchMode\s*=\s*"(singleTask|singleInstance)"', flags=re.IGNORECASE)


def find_manifests(search_dir: str = ".") -> List[str]:
    found = []
    for patt in MANIFEST_PATTERNS:
        for path in glob.glob(os.path.join(search_dir, patt)):
            if os.path.isfile(path):
                found.append(path)
    return sorted(list(dict.fromkeys(found)))


def get_attr_ns(elem: ET.Element, attr_name: str) -> Optional[str]:
    # 带命名空间的 key
    val = elem.get(f"{{{ANDROID_NS}}}{attr_name}")
    if val is None:
        val = elem.get(attr_name)
    return val


def analyze_manifest_xml(path: str) -> Tuple[Optional[bool], List[str]]:
    reasons: List[str] = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        return None, [f"xml_parse_error: {e}"]

    vulnerable = False
    # 查找所有 activity 和 activity-alias 元素（遍历 application 下的子孙）
    for tag in ("activity", "activity-alias"):
        for act in root.findall(f".//{tag}"):
            ta = get_attr_ns(act, "taskAffinity")
            lm = get_attr_ns(act, "launchMode")
            # 只在同一元素同时满足两条规则才计为漏洞
            if ta and ta.strip() and lm and lm.strip().lower() in ("singletask", "singleinstance"):
                vulnerable = True
                # 尝试获取可读名称
                name = get_attr_ns(act, "name") or act.get("android:name") or act.get("name") or "<unknown>"
                reasons.append(f"{tag} '{name}' has taskAffinity='{ta}' and launchMode='{lm}'")
    return vulnerable, reasons


def analyze_manifest_text(path: str) -> Tuple[Optional[bool], List[str]]:
    reasons: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception as e:
        return None, [f"read_error: {e}"]

    for m in RE_ACTIVITY_TAG.finditer(txt):
        attrs_text = m.group(1)
        m_ta = RE_TASK_AFF.search(attrs_text)
        m_lm = RE_LAUNCH.search(attrs_text)
        if m_ta and m_lm:
            ta_val = m_ta.group(1).strip()
            lm_val = m_lm.group(1).strip()
            reasons.append(f"activity tag fragment has taskAffinity='{ta_val}' and launchMode='{lm_val}'")
    vulnerable = len(reasons) > 0
    return vulnerable, reasons


def analyze_file(path: str) -> Tuple[Optional[bool], List[str]]:
    # try XML parse first
    xml_res, xml_reasons = analyze_manifest_xml(path)
    if xml_res is not None:
        if xml_res:
            logging.warning(f"{os.path.basename(path)} VULNERABLE (XML):")
            for r in xml_reasons:
                logging.warning(f"  - {r}")
        else:
            logging.warning(f"{os.path.basename(path)} OK (XML): no activity with both taskAffinity and singleTask/singleInstance launchMode")
        return xml_res, xml_reasons

    # fallback to text analysis
    text_res, text_reasons = analyze_manifest_text(path)
    if text_res is None:
        logging.warning(f"{os.path.basename(path)} cannot be analyzed: {text_reasons}")
        return None, text_reasons

    if text_res:
        logging.warning(f"{os.path.basename(path)} VULNERABLE (text search):")
        for r in text_reasons:
            logging.warning(f"  - {r}")
    else:
        logging.warning(f"{os.path.basename(path)} OK (text): no activity tag fragment with both attributes")
    return text_res, text_reasons


def run_check():
    manifests = find_manifests(".")
    if not manifests:
        logging.warning("no manifest-like files found in current directory using expected naming rules")
        return

    logging.warning(f"found {len(manifests)} manifest candidate(s): {manifests}")
    summary = []
    for path in manifests:
        res, reasons = analyze_file(path)
        summary.append((path, res, reasons))

    logging.warning("scan complete. summary:")
    for p, res, reasons in summary:
        bn = os.path.basename(p)
        if res is True:
            logging.warning(f"{bn}: VULNERABLE ({len(reasons)} reason(s))")
            return True
        elif res is False:
            logging.warning(f"{bn}: NOT VULNERABLE")
            return False
        else:
            logging.warning(f"{bn}: INCONCLUSIVE ({reasons})")
            return False



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
    'cve': 'CWE-1021',
    'year': 1021,
    'source_url': 'https://cwe.mitre.org/data/definitions/1021.html',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    "id": 'CWE-1021',
    "domain": "application",
    "vendor_product": "Android IVI Application",
    "component": 'strandhog_task_hijack',
    "type": 'security_misconfiguration',
    "summary": 'StrandHogg Task Hijacking 风险检测',
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
        "check_type": 'android_strandhog',
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
                    # ADB: check for singleTask/singleInstance activities via dumpsys
                    task_out = adb.shell(
                        f"dumpsys package {package} 2>/dev/null | grep -iE 'launchMode|taskAffinity' | head -20"
                        if package else "dumpsys activity activities 2>/dev/null | grep -i taskAffinity | head -10"
                    )
                    evidence["task_launch_info"] = task_out
                    vulnerable = None  # requires manifest static analysis for confirmation
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

class Poc14StrandhoggPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-019"
    meta_poc_name = 'CWE-1021 Android StrandHogg 任务劫持 Active Validation'
    meta_cve_id = 'CWE-1021'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/1021.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/1021.html']
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

    _desc = VULN.get("summary", "19_Android_StrandHogg_Task_Hijack_Audit") if "VULN" in dir() else "19_Android_StrandHogg_Task_Hijack_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc14StrandhoggPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

检测设备是否存在不安全的Service导出（存在暴露风险）...


在当前目录查找反编译/导出出的 AndroidManifest 文件（遵循之前命名规则）

判定规则（和你提供的一致）
1) 如果元素包含 android:exported="true" 则视为导出
2) 如果未设置 android:exported 属性 且该元素包含一个或多个 <intent-filter> 子元素 则视为导出

脚本行为
- 优先用 XML 解析（ElementTree），解析时正确处理 android 命名空间
- 若 XML 解析失败，则用文本正则回退判断（在单个 <service> 标签块内检测 intent-filter）
- 输出使用 logging.warning，不修改任何文件
- 搜索的 manifest 文件遵循之前的命名规则（例如 *_AndroidManifest.xml, *_AndroidManifest_text.txt 等）
"""
POC_TAG = "16. 检测设备app是否存在不安全的Service导出（存在暴露风险）..."

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
# match a full service block <service ...> ... </service>
RE_SERVICE_BLOCK = re.compile(r'<\s*service\b([^>]*)>(.*?)</\s*service\s*>', flags=re.IGNORECASE | re.DOTALL)
# match self-closing <service ... />
RE_SERVICE_SELF_CLOSING = re.compile(r'<\s*service\b([^>]*)/?>', flags=re.IGNORECASE | re.DOTALL)
RE_EXPORTED_ATTR = re.compile(r'\b(?:android:)?exported\s*=\s*"(true|false)"', flags=re.IGNORECASE)
RE_INTENT_FILTER = re.compile(r'<\s*intent-filter\b', flags=re.IGNORECASE)
RE_NAME_ATTR = re.compile(r'\b(?:android:)?name\s*=\s*"([^"]+)"', flags=re.IGNORECASE)


def find_manifests(search_dir: str = ".") -> List[str]:
    files = []
    for patt in MANIFEST_PATTERNS:
        for p in glob.glob(os.path.join(search_dir, patt)):
            if os.path.isfile(p):
                files.append(p)
    return sorted(list(dict.fromkeys(files)))


def get_attr_ns(elem: ET.Element, attr_name: str) -> Optional[str]:
    """Return attribute value trying android namespace then bare name."""
    v = elem.get(f"{{{ANDROID_NS}}}{attr_name}")
    if v is None:
        v = elem.get(attr_name)
    return v


def analyze_manifest_xml(path: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    """
    Parse manifest as XML and return list of vulnerable service entries.
    Each entry is dict: { 'name': <name>, 'reason': <str> }
    Returns (list_or_empty, None) on success, or (None, error_msg) on parse error.
    """
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        return None, f"xml parse error: {e}"

    results: List[dict] = []

    # find all service elements under application
    for elem in root.findall(".//service"):
        name = get_attr_ns(elem, "name") or elem.get("name") or "<unknown>"
        exported_attr = get_attr_ns(elem, "exported")
        # check intent-filter children
        has_intent = False
        for child in list(elem):
            tag_local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if tag_local == "intent-filter":
                has_intent = True
                break
        # apply rules
        if exported_attr is not None:
            if exported_attr.strip().lower() == "true":
                results.append({"name": name, "reason": 'android:exported="true"'})
        else:
            # no exported attribute: exported if intent-filter present
            if has_intent:
                results.append({"name": name, "reason": "no exported attribute and has intent-filter"})
    return results, None


def analyze_manifest_text(path: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    """
    Fallback textual analysis: find service blocks and decide exportedness.
    Returns (list_or_empty, None) on success, or (None, error_msg) on read error.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception as e:
        return None, f"read error: {e}"

    results: List[dict] = []

    # Full blocks
    for m in RE_SERVICE_BLOCK.finditer(txt):
        attr_text = m.group(1)
        inner = m.group(2)
        mname = RE_NAME_ATTR.search(attr_text)
        name = mname.group(1) if mname else "<unknown>"
        mex = RE_EXPORTED_ATTR.search(attr_text)
        if mex:
            val = mex.group(1).lower()
            if val == "true":
                results.append({"name": name, "reason": 'android:exported="true" (text)'})
            else:
                # explicit false -> not exported
                pass
            continue
        # no explicit exported attr: check inner for intent-filter
        if RE_INTENT_FILTER.search(inner):
            results.append({"name": name, "reason": "no exported attribute and has intent-filter (text)"})

    # Self-closing tags like <service ... />
    for m in RE_SERVICE_SELF_CLOSING.finditer(txt):
        attr_text = m.group(1)
        mname = RE_NAME_ATTR.search(attr_text)
        name = mname.group(1) if mname else "<unknown>"
        # avoid duplicates
        if any(r["name"] == name for r in results):
            continue
        mex = RE_EXPORTED_ATTR.search(attr_text)
        if mex:
            val = mex.group(1).lower()
            if val == "true":
                results.append({"name": name, "reason": 'android:exported="true" (self-closing text)'})
        else:
            # self-closing with no exported cannot have intent-filter inside -> not exported
            pass

    return results, None


def analyze_file(path: str) -> Tuple[Optional[List[dict]], List[str]]:
    """
    Try XML analysis first, fallback to text analysis.
    Returns (results_or_None, messages)
    """
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
    manifests = find_manifests(".")
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
            logging.warning(f"{os.path.basename(m)}: no exported services detected")
            overall.append((m, []))
            continue
        # report vulnerable services
        logging.warning(f"{os.path.basename(m)}: found {len(res)} exported service(s):")
        for r in res:
            logging.warning(f"  - [service] {r['name']}  reason: {r['reason']}")
        overall.append((m, res))

    # summary
    logging.warning("scan complete. summary:")
    for m, r in overall:
        bn = os.path.basename(m)
        if r is None:
            logging.warning(f"{bn}: INCONCLUSIVE")
            return False
        elif isinstance(r, list) and len(r) == 0:
            logging.warning(f"{bn}: OK (no exported services)")
            return False
        else:
            logging.warning(f"{bn}: VULNERABLE ({len(r)} exported entries)")
            return True


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc16ServiceExportPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备app是否存在不安全的Service导出（存在暴露风险）...'
    meta_cve_id = 'CWE-926'
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
        return execute_check_callable(run_check, self)

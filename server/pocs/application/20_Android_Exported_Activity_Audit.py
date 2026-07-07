#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""


检测设备是否存在不安全的Activity（及 activity-alias）导出（存在暴露风险）...


在当前目录查找反编译/导出出的 AndroidManifest 文件（遵循之前命名规则）

判定规则（与你提供的一致）
1) 如果元素包含 android:exported="true" 则视为导出
2) 如果未设置 android:exported 属性 且该元素包含一个或多个 <intent-filter> 子元素 则视为导出

脚本行为
- 优先用 XML 解析（ElementTree），解析时正确处理 android 命名空间
- 若 XML 解析失败，则用文本正则回退判断（在单个 activity/activity-alias 标签块内检测 intent-filter）
- 输出使用 logging.warning，不修改任何文件
- 搜索的 manifest 文件遵循之前的命名规则（例如 *_AndroidManifest.xml, *_AndroidManifest_text.txt 等）
"""
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
    """Return attribute value trying android namespace then bare name."""
    v = elem.get(f"{{{ANDROID_NS}}}{attr_name}")
    if v is None:
        v = elem.get(attr_name)
    return v


def analyze_manifest_xml(path: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    """
    Parse manifest as XML and return list of vulnerable activity entries.
    Each entry is dict: { 'type': 'activity'|'activity-alias', 'name': <name>, 'reason': <str> }
    Returns (list_or_empty, None) on success, or (None, error_msg) on parse error.
    """
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
    """
    Fallback textual analysis: find activity/activity-alias blocks and decide exportedness.
    Returns (list_or_empty, None) on success, or (None, error_msg) on read error.
    """
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


class Poc15ActivityExportPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备app是否存在不安全的Activity（及 activity-alias）导出（存在暴露风险）...'
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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

检测设备是否存在不安全的BroadcastReceiver导出（存在暴露风险）...

在当前目录查找反编译/导出出的 AndroidManifest 文件（遵循之前命名规则）
并检测 BroadcastReceiver（<receiver>）是否被导出（存在暴露风险）。

判定规则（与你提供的一致）：
1) 若 <receiver> 含 android:exported="true" -> 视为导出（有风险）
2) 若 未设置 android:exported 属性 且 <receiver> 包含一个或多个 <intent-filter> 子元素 -> 视为导出（有风险）

脚本行为
- 优先用 XML 解析（ElementTree），正确处理 android 命名空间
- 若 XML 解析失败，则用文本正则回退判断（在单个 <receiver> 块内检测 intent-filter）
- 输出使用 logging.warning，不修改任何文件
- 搜索的 manifest 文件遵循之前的命名规则（例如 *_AndroidManifest.xml, *_AndroidManifest_text.txt 等）
"""
POC_TAG = "18. 检测设备app是否存在不安全的BroadcastReceiver导出（存在暴露风险）..."
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
# match a full receiver block <receiver ...> ... </receiver>
RE_RECEIVER_BLOCK = re.compile(r'<\s*receiver\b([^>]*)>(.*?)</\s*receiver\s*>', flags=re.IGNORECASE | re.DOTALL)
# match self-closing <receiver ... />
RE_RECEIVER_SELF_CLOSING = re.compile(r'<\s*receiver\b([^>]*)/?>', flags=re.IGNORECASE | re.DOTALL)
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
    """返回带 android 命名空间或不带命名空间的属性值"""
    v = elem.get(f"{{{ANDROID_NS}}}{attr_name}")
    if v is None:
        v = elem.get(attr_name)
    return v


def analyze_manifest_xml(path: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    """
    使用 XML 解析 manifest，检查 <receiver> 元素的导出状态
    返回 (list_or_empty, None) 或 (None, error_msg)
    每个结果项为 {'name': ..., 'reason': ...}
    """
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        return None, f"xml parse error: {e}"

    results: List[dict] = []

    for elem in root.findall(".//receiver"):
        name = get_attr_ns(elem, "name") or elem.get("name") or "<unknown>"
        exported_attr = get_attr_ns(elem, "exported")
        # 检查是否包含 intent-filter 子元素
        has_intent = False
        for child in list(elem):
            tag_local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if tag_local == "intent-filter":
                has_intent = True
                break
        # 应用规则
        if exported_attr is not None:
            if exported_attr.strip().lower() == "true":
                results.append({"name": name, "reason": 'android:exported="true"'})
        else:
            # 未设置 exported 且 有 intent-filter 则视为导出
            if has_intent:
                results.append({"name": name, "reason": "no exported attribute and has intent-filter"})
    return results, None


def analyze_manifest_text(path: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    """
    文本回退解析：在每个 <receiver> 块或自闭合标签中检查 exported 属性或 intent-filter
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception as e:
        return None, f"read error: {e}"

    results: List[dict] = []

    # 处理完整块 <receiver ...> ... </receiver>
    for m in RE_RECEIVER_BLOCK.finditer(txt):
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
        # 未显式 exported：若内部包含 intent-filter 则视为导出
        if RE_INTENT_FILTER.search(inner):
            results.append({"name": name, "reason": "no exported attribute and has intent-filter (text)"})
            continue

    # 处理自闭合 <receiver ... />
    for m in RE_RECEIVER_SELF_CLOSING.finditer(txt):
        attr_text = m.group(1)
        mname = RE_NAME_ATTR.search(attr_text)
        name = mname.group(1) if mname else "<unknown>"
        # 跳过已在 results 中的（根据 name 去重）
        if any(r["name"] == name for r in results):
            continue
        mex = RE_EXPORTED_ATTR.search(attr_text)
        if mex:
            val = mex.group(1).lower()
            if val == "true":
                results.append({"name": name, "reason": 'android:exported="true" (self-closing text)'})
        else:
            # 自闭合标签没有内部 intent-filter，因此若无 exported 属性则一般不导出
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
            logging.warning(f"{os.path.basename(m)}: no exported broadcast receivers detected")
            overall.append((m, []))
            continue
        logging.warning(f"{os.path.basename(m)}: found {len(res)} exported receiver(s):")
        for r in res:
            logging.warning(f"  - [receiver] {r['name']}  reason: {r['reason']}")
        overall.append((m, res))

    # summary
    logging.warning("scan complete. summary:")
    for m, r in overall:
        bn = os.path.basename(m)
        if r is None:
            logging.warning(f"{bn}: INCONCLUSIVE")
            return False
        elif isinstance(r, list) and len(r) == 0:
            logging.warning(f"{bn}: OK (no exported receivers)")
            return False
        else:
            logging.warning(f"{bn}: VULNERABLE ({len(r)} exported entries)")
            return True


# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc18BrordcastExportPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备app是否存在不安全的BroadcastReceiver导出（存在暴露风险）...'
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

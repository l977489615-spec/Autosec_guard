#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测设备是否存在 StrandHogg 风险（CVE-2019-2215）...

检测规则修改版
只有当同一个 activity 或 activity-alias 元素同时满足：
  1) 包含 android:taskAffinity（非空）
  2) 包含 android:launchMode 且值为 singleTask 或 singleInstance
才判定为存在 StrandHogg 风险。

脚本会在当前目录查找 manifest-like 文件（遵循之前命名规则）。
优先使用 XML 解析，否则回退到文本正则匹配（在同一标签内匹配两属性）。
输出使用 logging.warning，不修改文件。
"""
POC_TAG = "14. 检测设备app是否存在StrandHogg风险（CVE-2019-2215）..."

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
    """
    获取带 android 命名空间或不带命名空间的属性值
    """
    # 带命名空间的 key
    val = elem.get(f"{{{ANDROID_NS}}}{attr_name}")
    if val is None:
        val = elem.get(attr_name)
    return val


def analyze_manifest_xml(path: str) -> Tuple[Optional[bool], List[str]]:
    """
    使用 XML 解析，逐个 activity / activity-alias 检查同一元素是否同时满足两个条件
    返回 (vulnerable_or_not_or_none_if_error, reasons)
    """
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
    """
    当 XML 解析失败时基于文本进行正则匹配
    检查每个 activity 或 activity-alias 起始标签内是否同时包含 taskAffinity 和 launchMode(singleTask|singleInstance)
    """
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


def main():
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


if __name__ == "__main__":
    main()

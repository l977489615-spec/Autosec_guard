#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""


在当前目录查找反编译/导出出的 AndroidManifest 文件（遵循之前命名规则）
并检测是否存在通过 intent-filter 声明的 scheme（如 <data android:scheme="myapp">）,
这类 scheme 会使浏览器或其他应用通过 URL (myapp://...) 启动对应的 Activity，
可能被用于 Intent Scheme URL attack（取决于实现与权限边界）。

规则（检测逻辑）
- 优先用 XML 解析（ElementTree），查找所有 <activity> 和 <activity-alias> 下的
  <intent-filter> -> <data android:scheme="..."> 条目，收集 scheme 与对应组件名。
- 若 XML 解析失败，则在文本中用正则回退查找 activity/activity-alias 块内出现
  data 标签并含有 android:scheme="..." 的情况（较宽松的字符串匹配）。
- 输出使用 logging.warning，列出每个 manifest 中发现的组件与 scheme 列表。
- 不修改或删除任何文件。

用法: 在包含 AndroidManifest 文件（或先前解包生成的 *_AndroidManifest.* 文件）的目录运行本脚本。
"""
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
    """
    Parse manifest as XML and find activities/activity-alias that declare data scheme(s).
    Returns (list_of_matches, None) on success, or (None, error_message) on parse error.
    Each match is: {'component_type': 'activity'|'activity-alias', 'name': <name>, 'schemes': [..], 'intent_filter_count': n}
    """
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
    """
    Fallback text-based analysis: scan activity/activity-alias blocks and search for data scheme attributes.
    Returns (list_of_matches, None) on success, or (None, error_msg) on failure.
    """
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


def main():
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

if __name__ == "__main__":
    main()

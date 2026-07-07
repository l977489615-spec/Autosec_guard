#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测设备是否存在不安全的ContentProvider导出（存在暴露风险）...

在当前目录查找反编译/导出出的 AndroidManifest 文件（遵循之前命名规则）
并检测  是否被导出（存在暴露风险）。

判定规则：
1) 如果元素包含 android:exported="true" 则视为导出
2) 对于 Android API <=16（老版本）且未设置 exported 属性的 ContentProvider 也视为导出
   - 这里假设无法直接获取 targetSdkVersion 时默认认为存在风险

脚本行为：
- 优先用 XML 解析（ElementTree），解析时正确处理 android 命名空间
- 若 XML 解析失败，则用文本正则回退判断（仅检查 android:exported="true" 的情况）
- 输出使用 logging.warning，不修改任何文件
- 搜索的 manifest 文件遵循之前的命名规则（例如 *_AndroidManifest.xml, *_AndroidManifest_text.txt 等）
"""

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
    """
    XML解析 ContentProvider
    Returns: list of dict { 'name':..., 'reason':... } or (None, error_msg)
    """
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
    """
    文本回退解析，检查 android:exported="true"
    """
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


class Poc17ProviderExportPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备app是否存在不安全的ContentProvider导出（存在暴露风险）...'
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

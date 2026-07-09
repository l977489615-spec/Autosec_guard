#!/usr/bin/env python3
"""
PoC Name  : 检测设备是否存在数据库泄露风险...
CVE       : CWE-200
Category  : application
Severity  : High
Type      : Type-A
Description: 检测设备是否存在数据库泄露风险... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 42_CWE_200_Android_Database_Export_Active_Validation.py <target_ip>
"""

from __future__ import annotations
POC_TAG = "38. 检测设备是否存在数据库泄露风险..."


import os
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Tuple

# 日志配置
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# 检测配置
# 1. 外部存储访问权限（允许App读写公共目录，可能存储数据库）
EXTERNAL_STORAGE_PERMISSIONS = {
    "android.permission.READ_EXTERNAL_STORAGE",  # 读取外部存储
    "android.permission.WRITE_EXTERNAL_STORAGE",  # 写入外部存储
    "android.permission.MANAGE_EXTERNAL_STORAGE"  # 管理外部存储（Android 11+）
}

# 2. 敏感数据权限（暗示App可能存储车辆/用户敏感数据到数据库）
SENSITIVE_DATA_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION",  # 精确定位（车辆轨迹）
    "android.permission.READ_PHONE_STATE",  # 读取手机状态（设备标识）
    "android.permission.GET_ACCOUNTS",  # 获取账户信息（用户账号）
    "android.permission.READ_CONTACTS",  # 读取联系人（隐私数据）
    "com.android.car.permission.READ_CAR_DATA"  # 读取车机数据（车辆状态、VIN等）
}

# 3. 外部存储写入相关配置（AndroidManifest中的直接配置）
EXTERNAL_STORAGE_CONFIGS = {
    "android:requestLegacyExternalStorage=\"true\"",  # 兼容旧版外部存储访问（Android 10+）
    "android:preserveLegacyExternalStorage=\"true\""  # 保留旧版外部存储权限
}


def find_manifest_files() -> List[str]:
    manifest_files = []
    current_dir = os.path.dirname(os.path.abspath(__file__))  # 脚本所在目录
    logging.info(f"开始扫描目录：{current_dir}")

    for filename in os.listdir(current_dir):
        # 匹配含"AndroidManifest"且后缀为.xml的文件
        if "AndroidManifest" in filename and filename.endswith(".xml"):
            file_path = os.path.join(current_dir, filename)
            manifest_files.append(file_path)
            logging.debug(f"找到目标文件：{file_path}")

    if not manifest_files:
        logging.warning("未找到任何AndroidManifest.xml文件（文件名需包含'AndroidManifest'）")
    else:
        logging.info(f"共找到 {len(manifest_files)} 个目标文件")
    return manifest_files


def parse_manifest_file(file_path: str) -> Tuple[List[str], List[str], List[str]]:
    external_perms = []
    sensitive_perms = []
    external_configs = []

    try:
        # 解析XML（忽略命名空间，简化查找）
        tree = ET.parse(file_path)
        root = tree.getroot()

        # 处理XML命名空间（若存在）
        ns = {}
        if root.tag.startswith("{"):
            ns_uri = root.tag.split("}", 1)[0][1:]
            ns = {"android": ns_uri}

        # 1. 查找所有权限声明（<uses-permission>）
        for perm_elem in root.findall(".//uses-permission", namespaces=ns):
            perm_name = perm_elem.get("{%s}name" % ns_uri) if ns else perm_elem.get("name")
            if not perm_name:
                continue

            # 判断是否为外部存储权限
            if perm_name in EXTERNAL_STORAGE_PERMISSIONS:
                external_perms.append(perm_name)
            # 判断是否为敏感数据权限
            elif perm_name in SENSITIVE_DATA_PERMISSIONS:
                sensitive_perms.append(perm_name)

        # 2. 查找Application标签中的外部存储配置（如requestLegacyExternalStorage）
        app_elem = root.find(".//application", namespaces=ns)
        if app_elem:
            # 检查requestLegacyExternalStorage
            legacy_storage = app_elem.get("{%s}requestLegacyExternalStorage" % ns_uri) if ns else app_elem.get(
                "requestLegacyExternalStorage")
            if legacy_storage and legacy_storage.lower() == "true":
                external_configs.append("android:requestLegacyExternalStorage=\"true\"")
            # 检查preserveLegacyExternalStorage
            preserve_storage = app_elem.get("{%s}preserveLegacyExternalStorage" % ns_uri) if ns else app_elem.get(
                "preserveLegacyExternalStorage")
            if preserve_storage and preserve_storage.lower() == "true":
                external_configs.append("android:preserveLegacyExternalStorage=\"true\"")

        # 3. 额外检查XML文本中是否包含外部存储配置（防止命名空间解析失败）
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            xml_content = f.read()
            for config in EXTERNAL_STORAGE_CONFIGS:
                if config in xml_content:
                    if config not in external_configs:
                        external_configs.append(config)

    except ET.ParseError as e:
        logging.error(f"解析文件失败 {file_path}：XML格式错误 - {str(e)}")
    except Exception as e:
        logging.error(f"处理文件失败 {file_path}：{str(e)}")

    return external_perms, sensitive_perms, external_configs


def assess_risk(external_perms: List[str], sensitive_perms: List[str], external_configs: List[str]) -> str:
    risk_level = "低风险"

    # 高风险：同时拥有外部存储权限 + 敏感数据权限（或外部存储配置）
    if (len(external_perms) > 0 and len(sensitive_perms) > 0) or (
            len(external_perms) > 0 and len(external_configs) > 0):
        risk_level = "高风险"
    # 中风险：仅拥有外部存储权限（无敏感数据权限），或仅拥有敏感数据权限（无外部存储权限）
    elif len(external_perms) > 0 or len(sensitive_perms) > 0:
        risk_level = "中风险"

    return risk_level


def generate_report(results: List[Dict]):
    logging.info("\n" + "=" * 80)
    logging.info("AndroidManifest.xml 数据库泄露风险检测报告")
    logging.info("=" * 80)

    for res in results:
        logging.info(f"\n【检测文件】：{res['file_path']}")
        logging.info(f"【风险等级】：{res['risk_level']}")
        logging.info(f"【外部存储权限】：{res['external_perms'] if res['external_perms'] else '无'}")
        logging.info(f"【敏感数据权限】：{res['sensitive_perms'] if res['sensitive_perms'] else '无'}")
        logging.info(f"【外部存储配置】：{res['external_configs'] if res['external_configs'] else '无'}")

        # 风险说明
        if res['risk_level'] == "高风险":
            logging.info("【风险说明】：App拥有外部存储访问权限（可能将数据库存储在公共目录），且声明了敏感数据权限（可能存储车辆/用户隐私），存在数据库泄露高风险！")
            return True
        elif res['risk_level'] == "中风险":
            logging.info("【风险说明】：App拥有外部存储权限（可能存储数据库到公共目录）或敏感数据权限（可能存储隐私数据），存在一定泄露风险，需进一步验证数据库存储位置和加密状态。")
            return True
        else:
            logging.info("【风险说明】：App未声明外部存储访问权限，且无敏感数据权限，数据库泄露风险较低（需确认数据库是否存储在App私有目录）。")
            return False

    logging.info("\n" + "=" * 80)
    logging.info("检测说明：")
    logging.info("1. 本脚本仅通过AndroidManifest.xml检测配置层面风险，无法验证数据库实际存储位置和加密状态；")
    logging.info("2. 高风险需进一步确认：是否将数据库存储在/sdcard等公共目录、数据库是否明文存储；")
    logging.info("3. 修复建议：避免在公共目录存储数据库，使用SQLCipher加密敏感数据，仅申请必要权限。")
    logging.info("=" * 80)


def run_check():
    # 步骤1：查找目标文件
    manifest_files = find_manifest_files()
    if not manifest_files:
        return

    # 步骤2：解析每个文件并检测特征
    results = []
    for file_path in manifest_files:
        external_perms, sensitive_perms, external_configs = parse_manifest_file(file_path)
        risk_level = assess_risk(external_perms, sensitive_perms, external_configs)

        results.append({
            "file_path": file_path,
            "external_perms": external_perms,
            "sensitive_perms": sensitive_perms,
            "external_configs": external_configs,
            "risk_level": risk_level
        })

    # 步骤3：生成报告
    return generate_report(results)



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
    'cve': 'CWE-200',
    'year': 200,
    'source_url': 'https://cwe.mitre.org/data/definitions/200.html',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    "id": 'CWE-200',
    "domain": "application",
    "vendor_product": "Android IVI Application",
    "component": 'database_export',
    "type": 'information_disclosure',
    "summary": '应用数据库泄露风险检测',
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
        "check_type": 'android_database_export',
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
                    # ADB: find accessible db files on device
                    db_out = adb.shell(
                        f"find /data/data/{package} -name '*.db' -readable 2>/dev/null | head -10"
                        if package else "find /sdcard -name '*.db' 2>/dev/null | head -10"
                    )
                    ext_db = adb.shell("find /sdcard -name '*.db' 2>/dev/null | head -5")
                    evidence["device_db_files"] = db_out
                    evidence["external_db_files"] = ext_db
                    pkg_info = adb.package_info(package) if package else ""
                    has_ext_storage = "WRITE_EXTERNAL_STORAGE" in pkg_info or "READ_EXTERNAL_STORAGE" in pkg_info
                    evidence["has_external_storage_perm"] = has_ext_storage
                    vulnerable = has_ext_storage or bool(db_out) if (has_ext_storage or db_out) else None
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

class Poc38DbExportPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-042"
    meta_poc_name = 'CWE-200 Android 数据库导出 Active Validation'
    meta_cve_id = 'CWE-200'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/200.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/200.html']
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

    _desc = VULN.get("summary", "42_Android_Database_Export_Audit") if "VULN" in dir() else "42_Android_Database_Export_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc38DbExportPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

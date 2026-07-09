#!/usr/bin/env python3
"""
PoC Name  : 检测设备是否存在系统日志泄露风险...
CVE       : CWE-532
Category  : application
Severity  : Medium
Type      : Type-A
Description: 检测设备是否存在系统日志泄露风险... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 43_CWE_532_Android_Syslog_Active_Validation.py <target_ip>
"""

from __future__ import annotations
POC_TAG = "39. 检测设备是否存在系统日志泄露风险..."


import os
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Tuple

# 日志配置
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# 检测核心配置
# 1. 日志访问/读写相关权限（允许App获取系统日志或读写日志文件）
LOG_RELATED_PERMISSIONS = {
    "android.permission.READ_LOGS",  # 读取系统日志（关键权限）
    "android.permission.WRITE_EXTERNAL_STORAGE",  # 写入外部存储（可能存储日志文件）
    "android.permission.READ_EXTERNAL_STORAGE",  # 读取外部存储（可能读取日志文件）
    "android.permission.MANAGE_EXTERNAL_STORAGE",  # 管理外部存储（Android 11+，日志文件访问）
    "com.android.server.pm.permission.GET_APP_OPS_STATS"  # 获取应用运行状态日志
}

# 2. 敏感组件导出（可被外部调用，可能泄露日志数据）
SENSITIVE_COMPONENTS = ["activity", "service", "provider", "receiver"]  # 四大组件
EXPORTED_ATTR = "android:exported"  # 导出属性

# 3. 日志存储/访问相关配置（Manifest中可能的日志相关配置项）
LOG_RELATED_CONFIGS = {
    "android:requestLegacyExternalStorage=\"true\"",  # 兼容旧版外部存储（日志文件可能存公共目录）
    "android:preserveLegacyExternalStorage=\"true\"",  # 保留旧版外部存储权限
    "log", "logger", "logfile", "logstore", "logdata"  # 配置中含日志相关关键词
}

# 4. 车机系统特殊日志权限（安卓车机场景补充）
CAR_LOG_PERMISSIONS = {
    "com.android.car.permission.READ_CAR_DIAGNOSTIC_LOGS",  # 读取车机诊断日志
    "com.android.car.permission.READ_CAR_SYSTEM_LOGS",  # 读取车机系统日志
    "com.byd.permission.READ_VEHICLE_LOGS"  # 车企自定义日志权限（示例）
}
# 合并所有权限检测列表
ALL_LOG_PERMISSIONS = LOG_RELATED_PERMISSIONS.union(CAR_LOG_PERMISSIONS)


def find_manifest_files() -> List[str]:
    manifest_files = []
    current_dir = os.path.dirname(os.path.abspath(__file__))  # 脚本所在目录
    logging.info(f"开始扫描目录：{current_dir}")

    for filename in os.listdir(current_dir):
        # 匹配规则：文件名含"AndroidManifest"且后缀为.xml
        if "AndroidManifest" in filename and filename.endswith(".xml"):
            file_path = os.path.join(current_dir, filename)
            manifest_files.append(file_path)
            logging.debug(f"找到目标文件：{file_path}")

    if not manifest_files:
        logging.warning("未找到任何AndroidManifest.xml文件（文件名需包含'AndroidManifest'）")
    else:
        logging.info(f"共找到 {len(manifest_files)} 个目标文件")
    return manifest_files


def parse_manifest_file(file_path: str) -> Tuple[List[str], List[str], List[str], List[str]]:
    log_perms = []
    exported_components = []
    log_configs = []
    log_keyword_items = []

    try:
        # 解析XML，处理命名空间（兼容不同格式的Manifest）
        tree = ET.parse(file_path)
        root = tree.getroot()
        ns = {}
        if root.tag.startswith("{"):
            ns_uri = root.tag.split("}", 1)[0][1:]
            ns = {"android": ns_uri}

        # 1. 检测日志相关权限（<uses-permission>标签）
        for perm_elem in root.findall(".//uses-permission", namespaces=ns):
            perm_name = perm_elem.get("{%s}name" % ns_uri) if ns else perm_elem.get("name")
            if perm_name and perm_name in ALL_LOG_PERMISSIONS:
                log_perms.append(perm_name)

        # 2. 检测导出的敏感组件（四大组件android:exported="true"）
        for comp_type in SENSITIVE_COMPONENTS:
            # 查找所有该类型组件（如<activity>、<service>）
            comp_elems = root.findall(f".//{comp_type}", namespaces=ns)
            for comp in comp_elems:
                comp_name = comp.get("{%s}name" % ns_uri) if ns else comp.get("name")
                exported = comp.get("{%s}exported" % ns_uri) if ns else comp.get("exported")

                # 判定导出：显式设为true，或未设置（Android 12+默认false，低版本默认true）
                if exported and exported.lower() == "true":
                    exported_components.append(f"{comp_type}（{comp_name or '未命名'}）")
                elif not exported:
                    # 未显式设置exported，标记为"默认导出（低版本风险）"
                    exported_components.append(f"{comp_type}（{comp_name or '未命名'}）- 未显式关闭导出（低版本风险）")

        # 3. 检测日志相关配置（Application标签中的存储兼容配置）
        app_elem = root.find(".//application", namespaces=ns)
        if app_elem:
            # 检查外部存储兼容配置（可能用于存储日志文件）
            legacy_storage = app_elem.get("{%s}requestLegacyExternalStorage" % ns_uri) if ns else app_elem.get(
                "requestLegacyExternalStorage")
            if legacy_storage and legacy_storage.lower() == "true":
                log_configs.append("android:requestLegacyExternalStorage=\"true\"（兼容旧版外部存储）")

            preserve_storage = app_elem.get("{%s}preserveLegacyExternalStorage" % ns_uri) if ns else app_elem.get(
                "preserveLegacyExternalStorage")
            if preserve_storage and preserve_storage.lower() == "true":
                log_configs.append("android:preserveLegacyExternalStorage=\"true\"（保留旧版外部存储权限）")

        # 4. 检测配置中含日志关键词的项（全局文本搜索，避免遗漏）
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            xml_content = f.read().lower()
            for keyword in LOG_RELATED_CONFIGS:
                if keyword.lower() in xml_content:
                    log_keyword_items.append(f"配置含关键词：{keyword}")

    except ET.ParseError as e:
        logging.error(f"解析文件失败 {file_path}：XML格式错误 - {str(e)}")
    except Exception as e:
        logging.error(f"处理文件失败 {file_path}：{str(e)}")

    return log_perms, exported_components, log_configs, log_keyword_items


def assess_risk(log_perms: List[str], exported_components: List[str], log_configs: List[str]) -> str:
    risk_level = "低风险"

    # 高风险：满足以下任一条件
    # 1. 拥有核心日志权限（如READ_LOGS） + 存在导出组件；
    # 2. 拥有车机日志权限 + 外部存储权限；
    # 3. 导出组件数量≥2 + 外部存储配置开启
    has_core_log_perm = any(perm in ["android.permission.READ_LOGS"] + list(CAR_LOG_PERMISSIONS) for perm in log_perms)
    has_external_storage_perm = any(
        perm in ["android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.MANAGE_EXTERNAL_STORAGE"] for perm in
        log_perms)
    has_exported_comp = len(exported_components) > 0
    has_log_config = len(log_configs) > 0

    if (has_core_log_perm and has_exported_comp) or (has_core_log_perm and has_external_storage_perm) or (
            len(exported_components) >= 2 and has_log_config):
        risk_level = "高风险"
    # 中风险：满足以下任一条件
    # 1. 仅拥有核心日志权限；
    # 2. 拥有外部存储权限 + 存在导出组件；
    # 3. 存在导出组件 + 日志相关配置开启
    elif has_core_log_perm or (has_external_storage_perm and has_exported_comp) or (
            has_exported_comp and has_log_config):
        risk_level = "中风险"
    # 低风险：无核心日志权限、无导出组件、无日志相关配置

    return risk_level


def generate_report(results: List[Dict]):
    logging.info("\n" + "=" * 80)
    logging.info("AndroidManifest.xml 系统日志泄露风险检测报告")
    logging.info("=" * 80)

    for res in results:
        logging.info(f"\n【检测文件】：{res['file_path']}")
        logging.info(f"【风险等级】：{res['risk_level']}")
        logging.info(f"【日志相关权限】：{res['log_perms'] if res['log_perms'] else '无'}")
        logging.info(f"【导出的敏感组件】：{res['exported_components'] if res['exported_components'] else '无'}")
        logging.info(f"【日志相关配置】：{res['log_configs'] if res['log_configs'] else '无'}")
        logging.info(f"【日志关键词配置】：{res['log_keyword_items'] if res['log_keyword_items'] else '无'}")

        # 风险说明（针对性解释）
        if res['risk_level'] == "高风险":
            logging.info("【风险说明】：App拥有核心日志访问权限（如读取系统/车机日志），且存在可导出组件或外部存储配置，"
                  "攻击者可能通过调用导出组件或访问公共目录日志文件，窃取系统敏感日志（如车辆诊断数据、用户操作记录）！")
            return True
        elif res['risk_level'] == "中风险":
            logging.info("【风险说明】：App拥有日志相关权限、导出组件或日志存储配置中的一项或多项，"
                  "存在潜在日志泄露风险（如日志文件被外部App读取、导出组件泄露日志数据），需进一步验证日志存储位置和访问控制。")
            return True
        else:
            logging.info("【风险说明】：App未声明核心日志权限，无敏感组件导出，且无日志相关存储配置，系统日志泄露风险较低。")
            return False

    logging.info("\n" + "=" * 80)
    logging.info("检测说明：")
    logging.info("1. 本脚本仅通过AndroidManifest.xml静态检测配置风险，无法验证日志实际存储位置、加密状态和访问控制；")
    logging.info("2. 高风险需进一步确认：是否将日志存储在/sdcard等公共目录、日志是否明文存储、导出组件是否泄露日志；")
    logging.info("3. 修复建议：")
    logging.info("   - 移除不必要的日志权限（如READ_LOGS），车机日志权限仅授予系统App；")
    logging.info("   - 显式关闭非必要组件的导出（android:exported=\"false\"）；")
    logging.info("   - 日志文件存储在App私有目录（/data/data/<package>/logs/），避免公共目录；")
    logging.info("   - 敏感日志需加密存储，导出组件需添加权限校验。")
    logging.info("=" * 80)


def run_check():
    # 步骤1：查找目标Manifest文件
    manifest_files = find_manifest_files()
    if not manifest_files:
        return

    # 步骤2：解析每个文件并提取风险特征
    results = []
    for file_path in manifest_files:
        log_perms, exported_components, log_configs, log_keyword_items = parse_manifest_file(file_path)
        risk_level = assess_risk(log_perms, exported_components, log_configs)

        results.append({
            "file_path": file_path,
            "log_perms": log_perms,
            "exported_components": exported_components,
            "log_configs": log_configs,
            "log_keyword_items": log_keyword_items,
            "risk_level": risk_level
        })

    # 步骤3：生成可视化报告
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
    'cve': 'CWE-532',
    'year': 532,
    'source_url': 'https://cwe.mitre.org/data/definitions/532.html',
    'affected': [{'vendor': 'Unknown', 'product': 'Unknown', 'versions': []}],
    "id": 'CWE-532',
    "domain": "application",
    "vendor_product": "Android IVI Application",
    "component": 'syslog_exposure',
    "type": 'information_disclosure',
    "summary": '系统日志泄露风险检测',
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
        "check_type": 'android_syslog_exposure',
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
                    # ADB: check for log-related permissions and actual log content
                    pkg_info = adb.package_info(package) if package else ""
                    has_log_perm = "READ_LOGS" in pkg_info
                    log_out = adb.shell(
                        "logcat -d -v brief 2>/dev/null | grep -iE 'password|token|secret|vin|session' | head -10"
                    )
                    evidence["has_read_logs_perm"] = has_log_perm
                    evidence["sensitive_log_sample"] = log_out
                    vulnerable = has_log_perm or bool(log_out) if (has_log_perm or log_out) else None
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

class Poc39SyslogExportPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-APP-043"
    meta_poc_name = 'CWE-532 Android Syslog Active Validation'
    meta_cve_id = 'CWE-532'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/532.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/532.html']
    meta_severity = 'Medium'
    meta_protocol = 'local'
    meta_target_os = ['android', 'linux']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['local_artifact']
    meta_attack_surface = '系统配置/本地制品'
    is_disruptive = False
    meta_destructive_level = 'Safe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        if _ACTIVE_VALIDATION_AVAILABLE and _run_active_validation is not None:
            return _run_active_validation(self, VULN, probe=_run_poc)
        return execute_check_callable(run_check, self)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "43_Android_Syslog_Exposure_Audit") if "VULN" in dir() else "43_Android_Syslog_Exposure_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc39SyslogExportPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

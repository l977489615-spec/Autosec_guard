#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
android_manifest_db_leak_scanner.py

静态检测AndroidManifest.xml中的数据库泄露风险特征
仅扫描脚本所在目录下所有含"AndroidManifest"的XML文件
检测维度：App是否允许外部存储访问、是否声明敏感权限（暗示数据库可能存储敏感数据）
"""
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
    """查找脚本所在目录下所有含"AndroidManifest"的XML文件"""
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
    """
    解析AndroidManifest.xml文件
    返回：(外部存储权限列表, 敏感数据权限列表, 外部存储配置列表)
    """
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
    """根据检测结果评估风险等级"""
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
    """生成检测报告"""
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


def main():
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


if __name__ == "__main__":
    main()
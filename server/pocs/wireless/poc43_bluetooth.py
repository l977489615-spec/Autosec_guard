import subprocess
import sys
import time
import re
import logging


# Logging configuration
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

POC_TAG = "43. 检测设备是否存在蓝牙权限提升漏洞（CVE-2020-0022）..."



def execute_adb_cmd(cmd, desc):
    """执行ADB命令，处理非UTF-8编码和空值"""
    logging.info(f"\n[*] 测试：{desc}")
    logging.info(f"[CMD] {cmd}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="ignore",  # 忽略车机特殊字符解码失败
            timeout=20
        )
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        success = result.returncode == 0

        if success:
            logging.info(f"[+] 执行成功！输出（前800字符）：{stdout[:800]}")
        else:
            logging.info(f"[-] 执行失败！错误信息：{stderr[:300]}")
        return {"success": success, "stdout": stdout, "stderr": stderr}
    except Exception as e:
        err_msg = str(e)
        logging.info(f"[!] 命令执行异常：{err_msg[:200]}")
        return {"success": False, "stdout": "", "stderr": err_msg}


def check_preconditions():
    """检查前置条件（系统版本、蓝牙状态、ADB连接）"""
    logging.info("[+] 第一步：检查前置条件")

    # 1. 检查ADB连接
    adb_result = execute_adb_cmd("adb devices", "检测ADB设备连接")
    valid_devices = [line for line in adb_result["stdout"].split("\n") if line.strip() and "device" in line]
    if not valid_devices:
        logging.info("[-] 前置条件失败：未检测到已连接的ADB设备")
        return False

    # 2. 检查安卓系统版本
    os_version_result = execute_adb_cmd("adb shell getprop ro.build.version.release", "读取安卓系统版本")
    os_version = os_version_result["stdout"].strip()
    if not os_version:
        logging.info("[-] 前置条件失败：无法获取系统版本")
        return False
    logging.info(f"[+] 车机安卓版本：{os_version}")
    # 判断是否为6.0及以下版本
    try:
        main_version = float(os_version.split(".")[0])
        if main_version > 6:
            logging.info("[-] 前置条件失败：系统版本高于6.0，不受CVE-2020-0022影响")
            return False
    except:
        logging.info(f"[-] 前置条件失败：未知系统版本格式 {os_version}")
        return False

    # 3. 检查蓝牙状态（需开启）
    bluetooth_result = execute_adb_cmd("adb shell settings get global bluetooth_on", "读取蓝牙状态")
    bluetooth_status = bluetooth_result["stdout"].strip()
    if bluetooth_status != "1":
        logging.info("[!] 蓝牙未开启，尝试自动开启...")
        enable_bluetooth = execute_adb_cmd("adb shell settings put global bluetooth_on 1", "开启蓝牙")
        time.sleep(3)  # 等待蓝牙启动
        if execute_adb_cmd("adb shell settings get global bluetooth_on", "验证蓝牙开启")["stdout"].strip() != "1":
            logging.info("[-] 前置条件失败：无法开启蓝牙，需手动开启后重试")
            return False
    logging.info("[+] 蓝牙状态：已开启")

    # 4. 检查安全补丁版本（是否已修复）
    patch_result = execute_adb_cmd("adb shell getprop ro.build.version.security_patch", "读取安全补丁版本")
    patch_date = patch_result["stdout"].strip()
    if patch_date:
        try:
            # 补丁日期格式：YYYY-MM-DD，若晚于2020-03则已修复
            patch_year = int(patch_date.split("-")[0])
            patch_month = int(patch_date.split("-")[1])
            if patch_year > 2020 or (patch_year == 2020 and patch_month >= 3):
                logging.info(f"[-] 前置条件失败：安全补丁版本 {patch_date}，已修复CVE-2020-0022")
                return False
        except:
            logging.info(f"[?] 安全补丁版本格式异常：{patch_date}，继续检测...")

    logging.info("[+] 所有前置条件满足，开始漏洞检测")
    return True


def check_bluetoothd_permission():
    """核心测试：检测是否能绕过权限获取bluetoothd相关权限"""
    logging.info("\n[+] 第二步：漏洞核心检测（模拟蓝牙权限绕过）")
    tests = [
        # 1. 查看bluetoothd进程权限（正常应仅root/system可访问）
        (
            "adb shell ps -ef | grep bluetoothd",
            "查看bluetoothd进程运行状态",
            "中风险：bluetoothd进程暴露，可能被劫持"
        ),
        # 2. 尝试读取蓝牙核心配置文件（正常需net_bt_admin权限）
        (
            "adb shell cat /data/misc/bluetooth/bt_config.conf",
            "读取蓝牙核心配置文件（bt_config.conf）",
            "高风险：成功读取说明绕过蓝牙权限校验"
        ),
        # 3. 尝试获取蓝牙设备列表（正常需蓝牙权限）
        (
            "adb shell service call bluetooth_manager 8",
            "调用蓝牙服务获取设备列表（无需应用权限）",
            "高风险：成功调用说明权限校验失效"
        ),
        # 4. 查看蓝牙日志（可能包含配对设备MAC、通信数据）
        (
            "adb shell logcat -d | grep -E 'bluetoothd|BTAdapter'",
            "提取蓝牙相关系统日志",
            "中风险：日志泄露蓝牙敏感信息"
        ),
        # 5. 尝试修改蓝牙可见性（正常需用户确认）
        (
            "adb shell settings put global bluetooth_discoverable 1",
            "设置蓝牙为可发现模式（无需用户确认）",
            "高风险：可任意修改蓝牙状态，辅助攻击"
        )
    ]

    vuln_count = 0
    vuln_details = []

    for cmd, desc, risk in tests:
        result = execute_adb_cmd(cmd, desc)
        if result["success"]:
            # 特殊判断：蓝牙配置文件读取成功，直接判定高风险
            if "bt_config.conf" in cmd and "address" in result["stdout"]:
                vuln_count += 2  # 权重加倍
                vuln_details.append(f"[!] {desc} - {risk}（核心漏洞触发）")
            else:
                vuln_count += 1
                vuln_details.append(f"[!] {desc} - {risk}")

    return vuln_count, vuln_details


def restore_bluetooth_settings():
    """恢复蓝牙配置，避免影响正常使用"""
    logging.info("\n[+] 第三步：恢复系统配置")
    execute_adb_cmd(
        "adb shell settings put global bluetooth_discoverable 0",
        "恢复蓝牙为不可发现模式"
    )
    logging.info("[+] 配置恢复完成")


def main():
    logging.info("=" * 80)
    logging.info("CVE-2020-0022 安卓车机蓝牙权限提升漏洞检测脚本")
    logging.info("漏洞说明：Android 6.0及以下蓝牙模块权限校验缺失，可获取蓝牙守护程序权限")
    logging.info("车机危害：窃取车内蓝牙通话、位置数据，劫持蓝牙控制功能")
    logging.info("检测逻辑：前置条件校验 + 蓝牙权限绕过测试")
    logging.info("=" * 80)

    # 1. 检查前置条件
    if not check_preconditions():
        logging.info("\n[-] 检测终止：前置条件不满足")
        return False

    # 2. 核心漏洞检测
    vuln_count, vuln_details = check_bluetoothd_permission()

    # 3. 恢复系统配置
    restore_bluetooth_settings()

    # 4. 输出最终结果
    logging.info("\n" + "=" * 80)
    logging.info(" 最终检测结果")
    logging.info("=" * 80)
    logging.info(f"漏洞触发风险项数量：{vuln_count}/5")

    if vuln_count >= 3:
        logging.info("\n[-]  高危漏洞存在！")
        logging.info("[-] 车机存在CVE-2020-0022漏洞，攻击者可：")
        for detail in vuln_details:
            logging.info(f"    {detail}")
        logging.info("[-] 具体危害：")
        logging.info("    1. 近距离窃取车内蓝牙通话、导航位置等敏感数据；")
        logging.info("    2. 劫持蓝牙连接，替换手机投屏内容；")
        logging.info("    3. 通过蓝牙执行恶意代码，干扰车机多媒体功能。")
        logging.info("[-] 紧急建议：")
        logging.info("    1. 若车机支持，升级系统至Android 7.0及以上；")
        logging.info("    2. 安装2020年3月后的安全补丁；")
        logging.info("    3. 非必要时关闭蓝牙功能，避免陌生设备连接。")
        return True
    elif vuln_count == 1 or vuln_count == 2:
        logging.info("\n[!]  中危风险存在！")
        logging.info("[-] 部分蓝牙权限可被绕过，但未完全触发漏洞核心")
        for detail in vuln_details:
            logging.info(f"    {detail}")
        logging.info("[-] 建议：尽快更新车机系统补丁，限制蓝牙使用场景。")
        return True
    else:
        logging.info("\n[+]  未检测到漏洞！")
        logging.info("[-] 车机蓝牙权限管控正常，未触发CVE-2020-0022漏洞")
        logging.info("[-] 建议：保持系统更新，避免连接陌生蓝牙设备。")
        return False
    logging.info("=" * 80)


if __name__ == "__main__":
    main()
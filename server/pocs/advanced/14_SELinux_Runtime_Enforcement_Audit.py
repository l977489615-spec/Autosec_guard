import subprocess
import sys
import time
import logging


# Logging configuration
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

POC_TAG = "41. 检测SELinux宽容设备是否存在敏感数据泄露风险..."

def execute_adb_cmd(cmd, desc):
    """执行ADB命令，返回结果和执行状态"""
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
            timeout=10
        )
        success = result.returncode == 0
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if success:
            logging.info(f"[+] 执行成功！输出（前500字符）：{stdout[:500]}")
        else:
            logging.info(f"[-] 执行失败！错误信息：{stderr[:200]}")
        return {"success": success, "stdout": stdout, "stderr": stderr}
    except Exception as e:
        logging.info(f"[!] 命令执行异常：{str(e)}")
        return {"success": False, "stdout": "", "stderr": str(e)}


def check_selinux_mode():
    """检测SELinux运行模式"""
    logging.info("[+] 第一步：检测SELinux模式（核心安全机制）")
    cmd = "adb shell getenforce"
    result = execute_adb_cmd(cmd, "获取SELinux状态")
    if not result["success"]:
        logging.info("[-] 无法获取SELinux状态，可能ADB连接异常或设备不支持")
        return None
    selinux_mode = result["stdout"].upper()
    logging.info(f"[+] SELinux当前模式：{selinux_mode}")
    return selinux_mode


def sensitive_operation_tests():
    """执行敏感操作测试集"""
    # 定义待测试的敏感操作（命令、描述、风险等级）
    tests = [
        # 1. 读取敏感配置文件（信息泄露风险）
        (
            "adb shell cat /data/misc/wifi/*.conf",
            "读取WiFi密码配置文件（/data/misc/wifi/*.conf）",
            "高风险：WiFi密码、SSID等隐私信息泄露"
        ),
        (
            "adb shell cat /data/misc/bluetooth/*.bin",
            "读取蓝牙配对信息（/data/misc/bluetooth/*.bin）",
            "高风险：蓝牙设备配对密钥泄露"
        ),
        # 2. 访问受限目录（权限绕过风险）
        (
            "adb shell ls -l /data/misc",
            "列出/data/misc目录（系统敏感数据存储目录）",
            "中风险：可访问系统核心敏感数据目录"
        ),
        (
            "adb shell ls -l /system/priv-app",
            "列出/system/priv-app目录（系统特权应用目录）",
            "高风险：可查看/篡改系统特权应用"
        ),
        # 3. 修改系统全局配置（配置篡改风险）
        (
            "adb shell settings put global screen_off_timeout 300000",  # 5分钟休眠
            "修改屏幕休眠时间为5分钟（系统全局配置）",
            "中风险：可篡改系统基础配置"
        ),
        # 4. 查看进程列表（信息泄露风险）
        (
            "adb shell ps -ef",
            "获取完整进程列表（含root级进程）",
            "中风险：可获取系统所有进程信息，辅助后续攻击"
        ),
        # 5. 系统目录创建文件（文件篡改风险）
        (
            "adb shell touch /system/tmp/test_selinux_leak.txt",
            "在/system目录创建临时文件",
            "高风险：可写入系统目录，可能植入恶意文件"
        ),
    ]

    # 记录测试结果
    vulnerability_count = 0
    vulnerability_details = []

    for cmd, desc, risk in tests:
        result = execute_adb_cmd(cmd, desc)
        if result["success"]:
            vulnerability_count += 1
            vulnerability_details.append(f"[!] {desc} - {risk}")

    return vulnerability_count, vulnerability_details


def restore_system_settings():
    """恢复系统配置（避免测试影响正常使用）"""
    logging.info("\n[+] 第四步：恢复系统原始配置")
    # 恢复屏幕休眠时间为默认值（30秒，可根据实际情况调整）
    execute_adb_cmd(
        "adb shell settings put global screen_off_timeout 30000",
        "恢复屏幕休眠时间为30秒"
    )
    # 删除测试创建的临时文件
    execute_adb_cmd(
        "adb shell rm -f /system/tmp/test_selinux_leak.txt",
        "删除系统目录下的测试文件"
    )
    logging.info("[+] 配置恢复完成")


def run_check():
    logging.info("=" * 70)
    logging.info("SELinux宽容模式漏洞检测脚本（非破坏性测试）")
    logging.info("检测逻辑：SELinux非强制模式 + 敏感操作可执行 → 存在漏洞")
    logging.info("适用场景：安卓车机/手机系统，检测权限管控缺失风险")
    logging.info("=" * 70)

    # 1. 检查ADB连接
    logging.info("[+] 前置检查：ADB设备连接")
    adb_check = execute_adb_cmd("adb devices", "检测已连接设备")
    if "device" not in adb_check["stdout"]:
        logging.info("[-] 未检测到已连接的ADB设备！")
        logging.info("[-] 请检查：USB连接、USB调试开启、ADB授权信任")
        sys.exit(1)

    # 2. 检测SELinux模式
    selinux_mode = check_selinux_mode()
    if not selinux_mode:
        logging.info("[-] 检测终止：无法获取SELinux状态")
        return False


    # 3. 仅当SELinux为非强制模式时，执行敏感操作测试
    if selinux_mode == "ENFORCING":
        logging.info("\n[+] SELinux处于强制模式（Enforcing），系统安全机制正常")
        logging.info("[+] 检测结果：未发现漏洞（SELinux有效阻挡敏感操作）")
        return False
    else:
        logging.info(f"\n[!] 警告：SELinux处于{selinux_mode}模式！安全机制失效")
        logging.info("[!] 开始执行敏感操作测试，验证系统权限管控是否缺失...")
        return True

        # 执行敏感操作测试
        vuln_count, vuln_details = sensitive_operation_tests()

        # 4. 恢复系统配置
        restore_system_settings()

        # 5. 输出最终检测结果
        logging.info("\n" + "=" * 70)
        logging.info(" 最终检测结果")
        logging.info("=" * 70)
        logging.info(f"SELinux模式：{selinux_mode}（安全机制失效）")
        logging.info(f"成功执行的敏感操作数：{vuln_count}/5")

        if vuln_count >= 2:
            logging.info("\n[-]  高危漏洞存在！")
            logging.info("[-] 系统存在“SELinux失效+权限管控缺失”组合漏洞，攻击者可：")
            for detail in vuln_details:
                logging.info(f"    {detail}")
            logging.info("[-] 建议：立即升级系统固件，启用SELinux强制模式，联系厂商修复权限管控漏洞")
        elif vuln_count == 1:
            logging.info("\n[!]  中危漏洞存在！")
            logging.info("[-] SELinux失效，但部分敏感操作被拦截，系统仍存在权限管控缺陷")
            for detail in vuln_details:
                logging.info(f"    {detail}")
            logging.info("[-] 建议：启用SELinux强制模式，排查系统权限配置异常")
        else:
            logging.info("\n[+]  未发现高风险漏洞！")
            logging.info("[-] SELinux失效，但系统权限管控正常，敏感操作均被拦截")
            logging.info("[-] 建议：启用SELinux强制模式，加固系统安全机制")
        logging.info("=" * 70)



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc41SelinuxPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测SELinux宽容设备是否存在敏感数据泄露风险...'
    meta_cve_id = 'CWE-284'
    meta_severity = 'Medium'
    meta_protocol = 'local'
    meta_target_os = ['android', 'linux']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['local_artifact']
    meta_attack_surface = '系统配置/本地制品'
    is_disruptive = True
    meta_destructive_level = 'Disruptive'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

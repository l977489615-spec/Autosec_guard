import subprocess
import sys
import time
import logging


# Logging configuration
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

POC_TAG = "40. 检测设备是否存在Zygote进程命令注入漏洞（CVE-2024-31317）..."

def execute_adb_command(cmd):
    """执行ADB命令并返回结果"""
    try:
        # 执行命令，捕获输出和错误
        result = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8"
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except Exception as e:
        return {"stdout": "", "stderr": f"命令执行异常: {str(e)}", "returncode": -1}


def check_adb_connection():
    """检查ADB是否已连接设备"""
    logging.info("[+] 正在检查ADB设备连接...")
    cmd = "adb devices"
    result = execute_adb_command(cmd)
    if result["returncode"] != 0:
        logging.info(f"[-] ADB命令执行失败: {result['stderr']}")
        return False
    # 过滤出已连接的设备（排除表头）
    devices = [line for line in result["stdout"].split("\n")[1:] if line.strip() and "device" in line]
    if not devices:
        logging.info("[-] 未检测到已连接的ADB设备，请确保设备开启USB调试并连接电脑")
        return False
    logging.info(f"[+] 已检测到 {len(devices)} 台设备：")
    for device in devices:
        logging.info(f"    - {device.split()[0]}")
    return True


def check_cve_2024_31317():
    """检测CVE-2024-31317漏洞"""
    # 1. 检查ADB连接
    if not check_adb_connection():
        sys.exit(1)

    # 2. 读取原始参数值
    logging.info("\n[+] 读取原始 hidden_api_blacklist_exemptions 参数...")
    get_cmd = "adb shell settings get global hidden_api_blacklist_exemptions"
    get_result = execute_adb_command(get_cmd)

    if get_result["returncode"] != 0:
        logging.info(f"[-] 读取参数失败: {get_result['stderr']}")
        # 部分系统可能未设置该参数，返回空值属于正常，继续检测
        original_value = None
    else:
        original_value = get_result["stdout"]
        logging.info(f"[+] 原始参数值: {original_value if original_value else '（空值）'}")

    # 3. 注入测试字符串（无恶意，仅用于验证权限）
    test_injection = "cve_test_2024_31317;test_cmd"
    logging.info(f"\n[+] 尝试注入测试字符串: {test_injection}")
    set_cmd = f"adb shell settings put global hidden_api_blacklist_exemptions \"{test_injection}\""
    set_result = execute_adb_command(set_cmd)

    if set_result["returncode"] != 0:
        logging.info(f"[-] 注入失败: {set_result['stderr']}")
        # 注入失败可能是权限管控正常，也可能是系统不支持该参数
        if "permission denied" in set_result["stderr"].lower():
            logging.info("[+] 检测结果：系统存在权限管控，未发现CVE-2024-31317漏洞风险")
        else:
            logging.info("[?] 检测结果：无法确定漏洞状态（系统不支持该参数或其他异常）")
            return False

    res = False
    # 4. 验证注入是否成功
    logging.info("[+] 验证注入结果...")
    verify_result = execute_adb_command(get_cmd)
    if verify_result["stdout"] == test_injection:
        logging.info("[-] 警告：注入成功！系统未对参数进行权限管控，存在CVE-2024-31317漏洞风险")
        logging.info("[-] 漏洞危害：攻击者可通过ADB注入恶意命令，实现用户态提权，操控系统核心功能")
        res = True
    else:
        logging.info("[+] 检测结果：注入未生效，系统存在权限管控，未发现漏洞风险")
        res = False

    # 5. 恢复原始参数（避免影响系统）
    logging.info("\n[+] 正在恢复原始参数...")
    if original_value is not None:
        restore_cmd = f"adb shell settings put global hidden_api_blacklist_exemptions \"{original_value}\""
    else:
        # 原始为空，删除该参数
        restore_cmd = "adb shell settings delete global hidden_api_blacklist_exemptions"

    restore_result = execute_adb_command(restore_cmd)
    if restore_result["returncode"] == 0:
        logging.info("[+] 原始参数恢复成功")
    else:
        logging.info(f"[-] 原始参数恢复失败: {restore_result['stderr']}，请手动检查系统配置")

    return res



def run_check():
    logging.info("=" * 60)
    logging.info("CVE-2024-31317 漏洞检测脚本")
    logging.info("漏洞描述：Zygote进程命令注入漏洞，可通过ADB注入恶意命令提权")
    logging.info("检测原理：读取并修改 hidden_api_blacklist_exemptions 参数，验证权限管控")
    logging.info("=" * 60)

    return check_cve_2024_31317()




# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


class Poc40ZygotePlugin(IVIVulnerabilityPlugin):
    meta_poc_name = '检测设备是否存在Zygote进程命令注入漏洞（CVE-2024-31317）...'
    meta_cve_id = 'CVE-2024-31317'
    meta_severity = 'Critical'
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

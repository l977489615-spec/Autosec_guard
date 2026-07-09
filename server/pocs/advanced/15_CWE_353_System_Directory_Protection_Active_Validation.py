#!/usr/bin/env python3
"""
PoC Name  : 检测设备dm_verity系统分区完整性验证是否开启...
CVE       : CWE-353
Category  : advanced
Severity  : Medium
Type      : Type-A
Description: 检测设备dm_verity系统分区完整性验证是否开启... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 15_CWE_353_System_Directory_Protection_Active_Validation.py <target_ip>
"""
from __future__ import annotations

import subprocess
import sys
import time
import logging


# Logging configuration
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

POC_TAG = "42. 检测设备dm_verity系统分区完整性验证是否开启..."

def execute_adb_cmd(cmd, desc):
    """执行ADB命令，返回结果字典（处理非UTF-8编码和空值）"""
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
            errors="ignore",  # 忽略无法解码的非UTF-8字符
            timeout=15
        )
        # 处理空值，避免None.strip()报错
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        success = result.returncode == 0

        if success:
            logging.info(f"[+] 执行成功！输出（前600字符）：{stdout[:600]}")
        else:
            logging.info(f"[-] 执行失败！错误信息：{stderr[:300]}")
        return {"success": success, "stdout": stdout, "stderr": stderr}
    except Exception as e:
        err_msg = str(e)
        logging.info(f"[!] 命令执行异常：{err_msg[:200]}")
        return {"success": False, "stdout": "", "stderr": err_msg}


def check_adb_connection():
    """检查ADB是否已连接设备"""
    logging.info("[+] 前置检查：ADB设备连接状态")
    result = execute_adb_cmd("adb devices", "检测已连接的ADB设备")
    # 过滤有效设备（排除表头和空行，包含"device"标识）
    valid_devices = [line for line in result["stdout"].split("\n") if line.strip() and "device" in line]
    if not valid_devices:
        logging.info("[-] 未检测到已连接的ADB设备！")
        logging.info("[-] 请确认：1. USB连接正常 2. 设备开启USB调试 3. 已授权ADB信任")
        return False
    logging.info(f"[+] 已检测到 {len(valid_devices)} 台有效设备：")
    for device in valid_devices:
        logging.info(f"    - {device.split()[0]}")
    return True


def check_dm_verity_status():
    """检测dm_verity验证机制状态"""
    logging.info("\n[+] 第一步：检测dm_verity系统分区完整性验证状态")
    cmd = "adb shell getprop ro.boot.veritymode"
    result = execute_adb_cmd(cmd, "读取ro.boot.veritymode属性")

    if not result["success"]:
        logging.info("[-] 无法获取dm_verity状态，可能设备不支持该属性或ADB权限不足")
        return None

    verity_mode = result["stdout"].lower().strip()
    logging.info(f"[+] dm_verity当前状态：{verity_mode}")

    if verity_mode not in ["enabled", "disabled"]:
        logging.info(f"[?] 未知状态：{verity_mode}（可能设备未适配dm_verity）")
        return None

    return verity_mode


def test_system_partition_permissions():
    """测试/system目录的读写权限（核心风险验证）"""
    logging.info("\n[+] 第二步：测试/system目录读写权限（普通ADB用户）")
    tests = [
        # 2. 尝试创建临时文件（写入权限测试）
        (
            "adb shell touch /system/tmp/dm_verity_test.txt",
            "在/system/tmp创建临时测试文件",
            "高风险：普通用户可写入系统目录，可植入恶意文件"
        ),
        # 3. 尝试修改系统非核心文件（修改权限测试，选择无影响的配置文件）
        (
            "adb shell echo 'test' >> /system/build.prop.bak",
            "向/system/build.prop.bak追加测试内容（备份文件，无影响）",
            "高风险：普通用户可修改系统文件，可篡改核心程序/配置"
        ),
        # 4. 查看/system/bin目录文件权限（简化命令，避免特殊字符报错）
        (
            "adb shell ls -l /system/bin | head -5",  # 只取前5行，减少特殊字符概率
            "查看/system/bin目录前5个核心程序权限",
            "高风险：若核心程序可修改，可替换为恶意版本"
        )
    ]

    # 记录风险项
    high_risk_count = 0
    risk_details = []

    for cmd, desc, risk in tests:
        result = execute_adb_cmd(cmd, desc)
        if result["success"]:
            high_risk_count += 1
            risk_details.append(f"[!] {desc} - {risk}")
        # 特殊处理：目录权限为777但未显式"成功"，但需识别权限风险
        if "ls -ld /system" in cmd and result["success"]:
            # 解析权限字符串（如drwxrwxrwx表示777）
            permission_str = result["stdout"].split()[0] if len(result["stdout"].split()) > 0 else ""
            if permission_str and permission_str[-3:] == "rwx":  # 其他用户有读写执行权限
                high_risk_count += 1
                risk_details.append(f"[!] /system目录权限为{permission_str} - 普通用户可任意修改系统文件")

    return high_risk_count, risk_details


def clean_test_files():
    """清理测试产生的临时文件，避免残留"""
    logging.info("\n[+] 第三步：清理测试残留文件")
    # 删除临时测试文件
    execute_adb_cmd(
        "adb shell rm -f /system/tmp/dm_verity_test.txt",
        "删除/system/tmp下的测试文件"
    )
    # 清理追加的测试内容（若文件存在）
    execute_adb_cmd(
        "adb shell sed -i '$d' /system/build.prop.bak",
        "删除build.prop.bak中追加的测试内容"
    )
    logging.info("[+] 残留文件清理完成")


def run_check():
    logging.info("=" * 75)
    logging.info("dm_verity系统分区完整性验证漏洞检测脚本（修复编码异常）")
    logging.info("漏洞说明：dm_verity禁用 → 系统分区可篡改 → 植入恶意程序/窃取数据")
    logging.info("检测逻辑：dm_verity状态 + /system目录读写权限 → 风险判断")
    logging.info("=" * 75)
    logging.info("️  警告：仅用于授权设备测试，禁止未授权测试他人设备！")
    logging.info("️  车机测试需在封闭场地进行，避免影响行车安全！")
    logging.info("=" * 75)


    # 1. 检查ADB连接
    if not check_adb_connection():
        logging.info("\n[-] 检测终止：ADB连接失败")
        return False

    # 2. 检测dm_verity状态
    verity_mode = check_dm_verity_status()
    if not verity_mode:
        logging.info("\n[-] 检测终止：无法确认dm_verity状态")
        return False


    # 3. 仅当dm_verity为disabled时，执行权限测试
    if verity_mode == "enabled":
        logging.info("\n[+]  dm_verity处于启用状态（enabled），系统分区完整性受保护")
        logging.info("[+] 检测结果：未发现漏洞（dm_verity正常工作）")
        logging.info("[-] 建议：保持dm_verity启用，定期更新系统固件")
        return False

    else:
        logging.info(f"\n[!]  警告：dm_verity处于禁用状态（disabled）！")
        logging.info("[!] 系统分区完整性验证失效，开始测试权限管控...")

        # 执行权限测试
        risk_count, risk_details = test_system_partition_permissions()

        # 清理测试残留
        clean_test_files()

        # 4. 输出最终结果
        logging.info("\n" + "=" * 75)
        logging.info(" 最终检测结果")
        logging.info("=" * 75)
        logging.info(f"dm_verity状态：disabled（验证机制失效）")
        logging.info(f"高风险权限项数量：{risk_count}")

        if risk_count >= 2:
            logging.info("\n[-]  高危漏洞存在！")
            logging.info("[-] 系统存在“dm_verity禁用+系统分区可篡改”组合漏洞，攻击者可：")
            for detail in risk_details:
                logging.info(f"    {detail}")
            logging.info("[-] 具体危害：替换导航/多媒体等核心程序、植入恶意代码、窃取用户隐私数据")
            logging.info("[-] 紧急建议：")
            logging.info("    1. 立即启用dm_verity（需root权限：adb shell setprop ro.boot.veritymode enabled）")
            logging.info("    2. 重新刷写官方系统固件，确保系统文件未被篡改")
            logging.info("    3. 限制ADB访问权限（关闭USB调试，禁用非信任设备连接）")
            return True
        elif risk_count == 1:
            logging.info("\n[!]  中危漏洞存在！")
            logging.info("[-] dm_verity已禁用，但仅部分权限可被滥用")
            for detail in risk_details:
                logging.info(f"    {detail}")
            logging.info("[-] 建议：启用dm_verity，排查系统权限配置异常")
            return True
        else:
            logging.info("\n[+]  未发现直接篡改风险！")
            logging.info("[-] dm_verity已禁用，但系统分区权限管控正常（普通用户无法修改）")
            logging.info("[-] 风险：仍存在被提权后篡改的可能，建议尽快启用dm_verity")
            return False
        logging.info("=" * 75)



# Standard plugin facade for the migrated legacy main() implementation.
from iv_plugin_base import IVIVulnerabilityPlugin
from poc_runtime_adapter import execute_check_callable


import sys as _sys, re as _re
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).parent))
from probe_utils import detection_confidence, ssh_exec


def _run_poc(plugin) -> dict:
    """SSH-based security hardening audit probe."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", ""))
    ssh_user  = params.get("ssh_user", "root")
    ssh_pass  = params.get("ssh_password")
    ssh_key   = params.get("ssh_key_file")
    adb_serial = params.get("adb_serial")

    evidence = {
        "check": 'World-writable system directories found',
        "target": target_ip or "local",
        "technique": "SSH remote command execution + output analysis",
    }

    cmd = "ls -la / /system /vendor 2>&1 | awk '{print $1, $3, $4, $NF}'"
    vuln_pattern = 'rwxrwxrwx|777'

    result_output = ""

    # Try ADB if no SSH target
    if adb_serial or (not target_ip):
        try:
            import subprocess as _sp
            adb_args = ["adb"]
            if adb_serial:
                adb_args += ["-s", adb_serial]
            adb_args += ["shell", cmd]
            r = _sp.run(adb_args, capture_output=True, text=True, timeout=15)
            result_output = r.stdout.strip() or r.stderr.strip()
            evidence["probe_method"] = "adb"
            evidence["adb_output"] = result_output[:500]
        except Exception as exc:
            evidence["adb_error"] = str(exc)

    # Try SSH
    if not result_output and target_ip:
        ssh_result = ssh_exec(target_ip, username=ssh_user,
                              password=ssh_pass, key_file=ssh_key, command=cmd)
        result_output = ssh_result.get("stdout", "") or ssh_result.get("stderr", "")
        evidence.update({
            "probe_method": "ssh",
            "ssh_output": result_output[:500],
            "ssh_error": ssh_result.get("error", ""),
        })

    # Try local execution
    if not result_output:
        try:
            import subprocess as _sp
            r = _sp.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            result_output = (r.stdout + r.stderr).strip()
            evidence["probe_method"] = "local"
            evidence["local_output"] = result_output[:500]
        except Exception as exc:
            evidence["local_error"] = str(exc)

    if not result_output:
        evidence["detail"] = (
            "No probe method succeeded. Provide target_ip (SSH) or adb_serial, "
            "or run in local mode. Manual check: " + cmd
        )
        conf = detection_confidence("E", evidence, "no_probe_available")
        return {"vulnerable": None, "evidence": evidence, "detection_confidence": conf,
                 "requires_manual_review": True}

    # Evaluate result
    _match = bool(_re.search(vuln_pattern, result_output, _re.IGNORECASE))
    evidence["probe_output"] = result_output[:500]
    evidence["vulnerability_pattern_matched"] = _match

    if _match:
        conf = detection_confidence("C", evidence, "remote_command_output_analysis")
        return {"vulnerable": True, "evidence": evidence, "detection_confidence": conf,
                 "requires_manual_review": True}
    else:
        conf = detection_confidence("C", evidence, "remote_command_output_analysis")
        return {"vulnerable": False, "evidence": evidence, "detection_confidence": conf}


class Poc42SystdirDisabledPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-ADV-015"
    meta_poc_name = 'CWE-353 System Directory Protection Active Validation'
    meta_cve_id = 'CWE-353'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/353.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/353.html']
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

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "15_System_Directory_Protection_Audit") if "VULN" in dir() else "15_System_Directory_Protection_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc42SystdirDisabledPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""
PoC Name  : 检测设备是否存在procfs进程信息泄露漏洞...
CVE       : CWE-200
Category  : advanced
Severity  : Medium
Type      : Type-A
Description: 检测设备是否存在procfs进程信息泄露漏洞... vulnerability detection.
Prerequisites: See HW_REQUIREMENTS or VULN dict for details.
Usage     : python3 16_CWE_200_ProcFS_Hidepid_Active_Validation.py <target_ip>
"""
from __future__ import annotations

import subprocess
import sys
import time
import logging


# Logging configuration
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

POC_TAG = "44. 检测设备是否存在procfs进程信息泄露漏洞..."


def execute_cmd(cmd, desc):
    """执行 Windows 命令，处理编码和空值（兼容 cmd/PowerShell）"""
    logging.info(f"\n[*] 测试：{desc}")
    logging.info(f"[CMD] {cmd}")
    try:
        # Windows 优先用 cmd 执行，兼容内置命令
        result = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="gbk",  # Windows cmd 默认编码为 GBK，避免中文乱码
            errors="ignore",
            timeout=10
        )
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        success = result.returncode == 0

        if success:
            logging.info(f"[+] 输出（前300字符）：{stdout[:300]}")
        else:
            logging.info(f"[-] 错误：{stderr[:200]}")
        return {"success": success, "stdout": stdout, "stderr": stderr}
    except Exception as e:
        err_msg = str(e)
        logging.info(f"[!] 异常：{err_msg[:150]}")
        return {"success": False, "stdout": "", "stderr": err_msg}


def check_adb_connection():
    """快速检查ADB连接"""
    logging.info("[+] 检查ADB连接...")
    result = execute_cmd("adb devices", "检测设备")
    if "device" not in result["stdout"]:
        logging.info("[-] 未找到已连接设备！请开启USB调试并授权")
        return False
    logging.info("[+] ADB连接正常")
    return True


def check_procfs_hidepid():
    """检测procfs是否启用hidepid=2（核心配置）"""
    logging.info("\n[+] 1. 检测procfs挂载配置")
    # adb shell 仅执行 mount | grep /proc，本地无需额外处理
    result = execute_cmd("adb shell mount | findstr proc", "查看/proc挂载参数")
    if "hidepid=2" in result["stdout"]:
        logging.info("[+] ✅ 已启用hidepid=2，配置正常")
        return True
    else:
        logging.info("[-] ❌ 未启用hidepid=2，procfs开放！")
        return False


def test_process_read():
    """测试能否读取任意非当前进程信息（Windows 本地处理结果）"""
    logging.info("\n[+] 2. 测试进程信息读取权限")
    # 关键调整：adb shell 仅执行 ps，后续过滤由 Windows cmd 处理
    # 命令逻辑：adb ps → 排除含shell的行 → 取第一行 → 提取第2列（PID）
    pid_cmd = 'for /f "tokens=2" %a in ("adb shell ps ^| findstr /v "shell" ^| more +1 ^| findstr /n "^" ^| findstr "^1:"") do @echo %a'
    pid_result = execute_cmd(pid_cmd, "获取目标进程PID")
    pid = pid_result["stdout"].strip()

    if not pid or not pid.isdigit():
        logging.info("[-] 未获取到目标PID，跳过读取测试")
        return False

    logging.info(f"[+] 目标进程PID：{pid}")
    # 尝试读取进程cmdline
    read_result = execute_cmd(f"adb shell cat /proc/{pid}/cmdline 2>/dev/null", f"读取/proc/{pid}/cmdline")
    if read_result["stdout"]:
        logging.info("[-]  成功读取到进程信息，存在泄露风险！")
        return True
    else:
        logging.info("[+]  无法读取进程信息，权限管控正常")
        return False


def run_check():
    logging.info("=" * 60)
    logging.info("procfs进程信息泄露漏洞（Windows适配）")
    logging.info("核心检测：hidepid配置 + 进程读取权限")
    logging.info("=" * 60)


    # 1. 检查ADB
    if not check_adb_connection():
        sys.exit(1)

    # 2. 核心检测
    hidepid_valid = check_procfs_hidepid()
    process_leak = test_process_read()

    # 3. 结果汇总
    logging.info("\n" + "=" * 60)
    logging.info(" 最终结果")
    logging.info("=" * 60)
    if not hidepid_valid and process_leak:
        logging.info("[-]  高危漏洞存在！")
        logging.info("[-] 修复建议：联系车企启用hidepid=2，或手动执行：")
        logging.info("    adb shell su -c 'mount -o remount,hidepid=2 /proc'（需root）")
    elif not hidepid_valid  and process_leak:
        logging.info("[!]  中危风险：未启用hidepid，但暂未泄露进程信息")
    elif hidepid_valid and not process_leak:
        logging.info("[+]  未检测到漏洞！安全配置正常")
    logging.info("=" * 60)

    return process_leak


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
        "check": '/proc mounted without hidepid protection',
        "target": target_ip or "local",
        "technique": "SSH remote command execution + output analysis",
    }

    cmd = "cat /proc/mounts 2>/dev/null | grep proc | grep -o 'hidepid=[0-9]' || echo hidepid=0"
    vuln_pattern = 'hidepid=0'

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


class Poc44ProcfsHidepidPlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-ADV-016"
    meta_poc_name = 'CWE-200 ProcFS Hidepid Active Validation'
    meta_cve_id = 'CWE-200'
    meta_source_url = 'https://cwe.mitre.org/data/definitions/200.html'
    meta_references = ['https://cwe.mitre.org/data/definitions/200.html']
    meta_severity = 'Medium'
    meta_protocol = 'local'
    meta_target_os = ['android', 'linux']
    meta_required_params = ['expected_usb_serial']
    meta_profiles = ['local_artifact']
    meta_attack_surface = '系统配置/本地制品'
    is_disruptive = False
    meta_destructive_level = 'Probe'

    def check_prerequisites(self):
        return True

    def exploit(self):
        return execute_check_callable(run_check, self)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "16_ProcFS_Hidepid_Audit") if "VULN" in dir() else "16_ProcFS_Hidepid_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc44ProcfsHidepidPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

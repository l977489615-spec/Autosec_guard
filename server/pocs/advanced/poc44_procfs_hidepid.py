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


def main():
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

if __name__ == "__main__":
    main()
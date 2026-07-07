"""共享工具：命令执行、ADB、热点客户端发现。"""
from __future__ import annotations

import os
import re
import subprocess
from typing import List, Tuple

ADB_CMD = "adb"
DEFAULT_CMD_TIMEOUT = 10.0


def run_cmd(cmd: list[str] | tuple[str, ...], timeout: float = DEFAULT_CMD_TIMEOUT) -> Tuple[int, str]:
    try:
        proc = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            encoding="utf-8",
            errors="ignore",
        )
        text = (proc.stdout or proc.stderr or "").strip()
        return proc.returncode, text
    except subprocess.TimeoutExpired:
        return -1, ""
    except FileNotFoundError as exc:
        return -2, str(exc)
    except Exception as exc:
        return -3, str(exc)


def is_private_lan_ip(ip: str) -> bool:
    if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
        return False
    if ip.startswith("192.168.") or ip.startswith("10."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    return False


def get_hotspot_clients() -> List[str]:
    """从 arp 表提取疑似连接热点的私网 IP。"""
    code, output = run_cmd(["arp", "-a"], timeout=1.0)
    if code < 0:
        return []
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", output)
    valid: list[str] = []
    for ip in ips:
        if ip.startswith(("127.", "0.", "255.")):
            continue
        if is_private_lan_ip(ip):
            valid.append(ip)
    return sorted(set(valid))


def get_scan_targets(explicit_target_ip: str | None = None) -> List[str]:
    """
    扫描目标 IP 列表：优先实验注入的 AUTOSEC_TARGET_IP（Mock/实车），否则热点 ARP。
  """
    env_ip = str(os.environ.get("AUTOSEC_TARGET_IP") or "").strip()
    if env_ip:
        return [env_ip]
    if explicit_target_ip and str(explicit_target_ip).strip():
        return [str(explicit_target_ip).strip()]
    return get_hotspot_clients()


def list_adb_devices(authorized_only: bool = True) -> List[str]:
    code, out = run_cmd([ADB_CMD, "devices"], timeout=4.0)
    if code < 0 or not out:
        return []
    devices: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("list of devices"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if authorized_only and parts[1] != "device":
            continue
        if ":" in parts[0] or parts[0].startswith("emulator-"):
            continue
        devices.append(parts[0])
    return devices


def resolve_adb_serial(explicit: str | None = None) -> str | None:
    serial = str(explicit or "").strip()
    if serial:
        return serial
    devices = list_adb_devices()
    if len(devices) == 1:
        return devices[0]
    return None

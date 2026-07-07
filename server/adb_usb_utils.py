"""本机 USB ADB 探测：实验策略默认仅允许 1 台 USB Android 设备。"""
from __future__ import annotations

import subprocess


def list_local_usb_adb_serials(timeout: int = 4) -> list[str]:
    try:
        proc = subprocess.run(
            ["adb", "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    serials: list[str] = []
    for raw_line in proc.stdout.splitlines()[1:]:
        line = raw_line.strip()
        if not line or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        if ":" in serial or serial.startswith("emulator-"):
            continue
        if state not in {"device", "unauthorized", "authorizing", "offline"}:
            continue
        serials.append(serial)
    return serials


def usb_adb_device_count(timeout: int = 4) -> int:
    return len(list_local_usb_adb_serials(timeout=timeout))


def usb_adb_status(timeout: int = 4) -> tuple[bool, str, list[str]]:
    """返回 (是否满足「恰好 1 台」策略, 该台 serial 或空, 当前全部 serial 列表)。"""
    serials = list_local_usb_adb_serials(timeout=timeout)
    if len(serials) == 0:
        return False, "", serials
    if len(serials) == 1:
        return True, serials[0], serials
    return False, "", serials


def usb_adb_block_reason(timeout: int = 4) -> str:
    serials = list_local_usb_adb_serials(timeout=timeout)
    if not serials:
        return "未检测到 USB 直连 ADB 设备（adb devices 为空）。"
    if len(serials) > 1:
        return (
            f"检测到 {len(serials)} 台 USB ADB 设备，实验要求仅连接 1 台。"
            f"请拔掉多余设备后重试。当前: {', '.join(serials)}"
        )
    return ""


def local_usb_adb_attached(timeout: int = 4) -> bool:
    """仅当恰好 1 台 USB 设备时视为可用。"""
    return usb_adb_device_count(timeout=timeout) == 1


def resolve_usb_adb_serial(explicit: str = "", *, auto_single: bool = True, timeout: int = 4) -> str:
    """显式 serial 优先；未指定时仅在本机恰好 1 台 USB 设备时返回其 serial。"""
    explicit = str(explicit or "").strip()
    serials = list_local_usb_adb_serials(timeout=timeout)
    if explicit:
        return explicit
    if auto_single and len(serials) == 1:
        return serials[0]
    return ""

#!/usr/bin/env python3
import json
import shutil
import subprocess
import re
import socket
from pathlib import Path


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
        return result.stderr.strip()
    except Exception as exc:
        return str(exc)


def _which(name: str) -> bool:
    return shutil.which(name) is not None


def _probe_python_can() -> dict:
    result = {
        "available": False,
        "detected_configs": [],
        "interfaces": [],
        "error": "",
    }
    try:
        import can

        result["available"] = True
        detect_fn = getattr(can, "detect_available_configs", None)
        if callable(detect_fn):
            configs = detect_fn(["pcan", "socketcan", "slcan"])
            normalized = []
            interfaces = set()
            for item in configs or []:
                if not isinstance(item, dict):
                    continue
                normalized.append(item)
                interface_name = str(item.get("interface") or "").strip()
                channel_name = str(item.get("channel") or "").strip()
                if interface_name:
                    interfaces.add(interface_name)
                if channel_name:
                    interfaces.add(channel_name)
            result["detected_configs"] = normalized
            result["interfaces"] = sorted(interfaces)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _probe_networks() -> list[str]:
    """
    Probes local network interfaces and extracts CIDR subnets (e.g. 192.168.1.0/24).
    Works on macOS (ifconfig) and Linux (ip addr).
    """
    subnets = []
    try:
        # 1. Try Linux 'ip -4 addr'
        if shutil.which("ip"):
            res = subprocess.run(["ip", "-4", "addr", "show"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    # Look for 'inet 192.168.1.5/24 ...'
                    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
                    if match:
                        cidr = match.group(1)
                        if not cidr.startswith("127."):
                            subnets.append(cidr)
        
        # 2. Try macOS/BSD 'ifconfig' (if 'ip' failed or not found)
        if not subnets and shutil.which("ifconfig"):
            res = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                # Parsing ifconfig for inet and netmask is slightly more complex
                # We'll use a simplified regex approach for common LAN patterns
                for line in res.stdout.splitlines():
                    if "inet " in line and "127.0.0.1" not in line:
                        # Logic: Extract IP and find the subnet mask
                        # Format: inet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255
                        parts = line.split()
                        try:
                            addr = parts[parts.index("inet") + 1]
                            if "netmask" in parts:
                                mask_hex = parts[parts.index("netmask") + 1]
                                if mask_hex.startswith("0x"):
                                    # Convert 0xffffff00 -> 24
                                    mask_val = int(mask_hex, 16)
                                    cidr_bits = bin(mask_val).count('1')
                                    subnets.append(f"{addr}/{cidr_bits}")
                                else:
                                    # Fallback to /24 if mask parsing is weird
                                    subnets.append(f"{addr}/24")
                            else:
                                subnets.append(f"{addr}/24")
                        except (ValueError, IndexError):
                            continue
    except Exception:
        pass
    
    # 3. Last fallback: just the hostname IP
    if not subnets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            if local_ip:
                subnets.append(f"{local_ip}/24")
        except Exception:
            pass

    return sorted(list(set(subnets)))


def probe() -> dict:
    usb_mounts = []
    for base in [Path("/media"), Path("/mnt"), Path("/Volumes")]:
        if base.exists():
            for child in sorted(base.iterdir()):
                if child.is_dir():
                    usb_mounts.append(str(child))

    # Advanced hardware detection for automotive / PCAN
    pcan_chardevs = sorted(str(path) for path in Path("/dev").glob("pcan*"))
    lsusb_output = _run(["lsusb"]) if _which("lsusb") else ""
    python_can = _probe_python_can()
    
    return {
        "networks": _probe_networks(),
        "host_tools": {
            "lsusb": _which("lsusb"),
            "ip": _which("ip"),
            "iw": _which("iw"),
            "bluetoothctl": _which("bluetoothctl"),
            "hciconfig": _which("hciconfig"),
            "hackrf_info": _which("hackrf_info"),
            "rtl_test": _which("rtl_test"),
        },
        "python_can": python_can,
        "usb": {
            "lsusb": lsusb_output,
            "is_pcan_present": "PEAK System" in lsusb_output,
            "mount_candidates": usb_mounts,
            "tty_usb": sorted(str(path) for path in Path("/dev").glob("ttyUSB*")),
        },
        "socketcan": {
            "interfaces": _run(["ip", "-details", "link", "show"]) if _which("ip") else "",
            "can_detected": " can" in (_run(["ip", "link", "show"]) if _which("ip") else ""),
        },
        "pcan_chardev": {
            "present": len(pcan_chardevs) > 0,
            "devices": pcan_chardevs,
            "proc_pcan": _run(["cat", "/proc/pcan"]) if Path("/proc/pcan").exists() else "",
        },
        "wifi": {
            "interfaces": _run(["iw", "dev"]) if _which("iw") else "",
        },
        "bluetooth": {
            "bluetoothctl_list": _run(["bluetoothctl", "list"]) if _which("bluetoothctl") else "",
            "hciconfig": _run(["hciconfig"]) if _which("hciconfig") else "",
        },
        "sdr": {
            "hackrf_info": _run(["hackrf_info"]) if _which("hackrf_info") else "",
            "rtl_test": _run(["rtl_test", "-t"]) if _which("rtl_test") else "",
        },
    }


def main() -> int:
    print(json.dumps(probe(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

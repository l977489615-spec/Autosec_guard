#!/usr/bin/env python3
import json
import shutil
import subprocess
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


def probe() -> dict:
    usb_mounts = []
    for base in [Path("/media"), Path("/mnt"), Path("/Volumes")]:
        if base.exists():
            for child in sorted(base.iterdir()):
                if child.is_dir():
                    usb_mounts.append(str(child))

    return {
        "host_tools": {
            "lsusb": _which("lsusb"),
            "ip": _which("ip"),
            "iw": _which("iw"),
            "bluetoothctl": _which("bluetoothctl"),
            "hciconfig": _which("hciconfig"),
            "hackrf_info": _which("hackrf_info"),
            "rtl_test": _which("rtl_test"),
        },
        "usb": {
            "lsusb": _run(["lsusb"]) if _which("lsusb") else "",
            "mount_candidates": usb_mounts,
            "tty_usb": sorted(str(path) for path in Path("/dev").glob("ttyUSB*")),
        },
        "socketcan": {
            "interfaces": _run(["ip", "-details", "link", "show"]) if _which("ip") else "",
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

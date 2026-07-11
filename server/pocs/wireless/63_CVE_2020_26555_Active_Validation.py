#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_bt_impersonation_env() -> dict:
    """Check environment for BT Classic impersonation attack capability."""
    info = {
        "bluez_version": "",
        "potentially_vulnerable": None,
        "hcitool_available": False,
    }
    # Check BlueZ version - CVE-2020-26555 fixed in BlueZ 5.56+
    try:
        r = subprocess.run(
            ["bluetoothd", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        version_text = (r.stdout + r.stderr).strip()
        info["bluez_version"] = version_text[:200]
        m = re.search(r'(\d+)\.(\d+)', version_text)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if major == 5 and minor < 56:
                info["potentially_vulnerable"] = True
            elif major < 5:
                info["potentially_vulnerable"] = True
            else:
                info["potentially_vulnerable"] = False
    except FileNotFoundError:
        info["bluez_error"] = "bluetoothd not found"
    except subprocess.TimeoutExpired:
        info["bluez_error"] = "timeout"

    try:
        r = subprocess.run(["hcitool", "dev"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if line.strip().startswith("hci"):
                info["hcitool_available"] = True
                break
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return info


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    bt_mac = params.get("bluetooth_mac") or params.get("bt_mac", "")

    evidence = {
        "cve": "CVE-2020-26555",
        "target": bt_mac or "Bluetooth Classic device (BT impersonation auth bypass)",
        "technique": (
            "BT Classic impersonation audit: check BlueZ version for "
            "unauthenticated pairing acceptance when PIN is all-zeros"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-26555",
        "vuln_detail": (
            "BT Classic impersonation: device accepts all-zero PIN during pairing, "
            "allowing attacker to impersonate any paired device without secret."
        ),
        "attack_scenario": (
            "1. Attacker spoofs MAC address of known paired device\n"
            "2. Initiates BT pairing with zero PIN\n"
            "3. Target accepts zero-PIN auth → attacker authenticated as legitimate device"
        ),
    }

    env_info = _check_bt_impersonation_env()
    evidence["bt_environment"] = env_info

    if env_info.get("potentially_vulnerable") is True:
        vulnerable = True
        evidence["note"] = (
            f"BlueZ {env_info['bluez_version']} is in impersonation-vulnerable range (< 5.56). "
            "CVE-2020-26555 BT Classic impersonation bypass applicable."
        )
    elif env_info.get("potentially_vulnerable") is False:
        vulnerable = False
        evidence["note"] = "BlueZ version appears patched for BT impersonation (>= 5.56)"
    else:
        vulnerable = None
        evidence["note"] = (
            "Cannot determine BT impersonation exposure. "
            "Requires two BT Classic adapters: one to spoof MAC, one to initiate zero-PIN pairing."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 78,
    "cve": "CVE-2020-26555",
    "year": 2020,
    "domain": "蓝牙/协议",
    "vendor_product": "Bluetooth BR/EDR",
    "component": "Impersonation",
    "type": "认证绕过",
    "summary": "Bluetooth Classic冒充攻击，影响配对信任模型。",
    "source_description": "Bluetooth legacy BR/EDR PIN code pairing in Bluetooth Core Specification 1.0B through 5.2 may permit an unauthenticated nearby device to spoof the BD_ADDR of the peer device to complete pairing without knowledge of the PIN.",
    "poc_status": "有公开研究/PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-26555",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-26555",
        "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/reporting-security/",
        "https://kb.cert.org/vuls/id/799380",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NSS6CTGE4UGTJLCOZOASDR3T3SLL6QJZ/",
        "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00520.html",
        "https://cveawg.mitre.org/api/cve/CVE-2020-26555"
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
        "CVE-2020-26555",
        "Bluetooth",
        "EDR",
        "Impersonation",
        "legacy",
        "code",
        "pairing",
        "Core",
        "Specification",
        "permit",
        "unauthenticated",
        "nearby",
        "device",
        "spoof",
        "BD_ADDR",
        "peer",
        "complete",
        "without",
        "knowledge",
        "PIN"
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

class Poc63CVE202026555AuthBypassAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-063"
    meta_poc_name = 'CVE-2020-26555 认证绕过 Active Validation'
    meta_cve_id = 'CVE-2020-26555'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2020-26555'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2020-26555']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "63_BT_Classic_Impersonation_Auth_Bypass_Audit") if "VULN" in dir() else "63_BT_Classic_Impersonation_Auth_Bypass_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc63CVE202026555AuthBypassAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

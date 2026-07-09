#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_bluez_bias_version() -> dict:
    """Check BlueZ version for BIAS vulnerability (CVE-2020-10135)."""
    info = {"bluez_version": "", "potentially_vulnerable": None}
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
            # BIAS fixed in BlueZ 5.55 (June 2020 patches)
            if major == 5 and minor < 55:
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


def _check_bt_classic_mode(mac: str) -> dict:
    """Check if target device is in BT Classic mode (required for BIAS)."""
    info = {"reachable": False, "device_class": "", "error": ""}
    try:
        r = subprocess.run(
            ["hcitool", "info", mac],
            capture_output=True, text=True, timeout=10,
        )
        info["reachable"] = r.returncode == 0
        output = r.stdout + r.stderr
        info["device_info"] = output[:300]
        m = re.search(r'Device Class:\s+(.+)', output)
        if m:
            info["device_class"] = m.group(1).strip()
    except FileNotFoundError:
        info["error"] = "hcitool not found"
    except subprocess.TimeoutExpired:
        info["error"] = "timeout"
    return info


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    bt_mac = params.get("bluetooth_mac") or params.get("bt_mac", "")

    evidence = {
        "cve": "CVE-2020-10135",
        "target": bt_mac or "Bluetooth Classic device (BIAS auth bypass)",
        "technique": (
            "BIAS (Bluetooth Impersonation AttackS) audit: check BlueZ version, "
            "verify target BT Classic reachability, probe for secure auth downgrade"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-10135",
        "vuln_detail": (
            "BIAS: attacker can impersonate a paired device by role-switching during "
            "auth and claiming legacy auth completion without actual auth challenge."
        ),
        "affected_spec": "Bluetooth Core Specification 5.2 and earlier",
    }

    bluez_info = _check_bluez_bias_version()
    evidence["bluez_version_check"] = bluez_info

    if bt_mac:
        bt_info = _check_bt_classic_mode(bt_mac)
        evidence["bt_device_info"] = bt_info
    else:
        evidence["bt_device_info"] = {"note": "no bluetooth_mac provided"}

    if bluez_info.get("potentially_vulnerable") is True:
        vulnerable = True
        evidence["note"] = (
            f"BlueZ {bluez_info['bluez_version']} is in BIAS-vulnerable range (< 5.55). "
            "CVE-2020-10135 authentication bypass is applicable."
        )
    elif bluez_info.get("potentially_vulnerable") is False:
        vulnerable = False
        evidence["note"] = "BlueZ version appears patched for BIAS"
    else:
        vulnerable = None
        evidence["note"] = (
            "Cannot determine BIAS exposure without BlueZ version. "
            "BIAS requires two BT Classic adapters and paired device knowledge."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 77,
    "cve": "CVE-2020-10135",
    "year": 2020,
    "domain": "蓝牙/协议",
    "vendor_product": "Bluetooth BR/EDR",
    "component": "BIAS",
    "type": "认证绕过",
    "summary": "Bluetooth BIAS攻击可冒充已配对设备。",
    "source_description": "Legacy pairing and secure-connections pairing authentication in Bluetooth BR/EDR Core Specification v5.2 and earlier may allow an unauthenticated user to complete authentication without pairing credentials via adjacent access. An unauthenticated, adjacent attacker could impersonate a Bluetooth BR/EDR master or slave to pair with a previously paired remote device to successfully complete the authentication procedure without knowing the link key.",
    "poc_status": "有公开研究/PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-10135",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-10135",
        "https://kb.cert.org/vuls/id/647177/",
        "http://seclists.org/fulldisclosure/2020/Jun/5",
        "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00009.html",
        "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00047.html",
        "https://francozappa.github.io/about-bias/",
        "https://www.bluetooth.com/learn-about-bluetooth/bluetooth-technology/bluetooth-security/bias-vulnerability/",
        "http://packetstormsecurity.com/files/157922/Bluetooth-Impersonation-Attack-BIAS-Proof-Of-Concept.html",
        "https://cveawg.mitre.org/api/cve/CVE-2020-10135"
    ],
    "affected": [
        {
            "vendor": "Bluetooth",
            "product": "BR/EDR",
            "versions": [
                {
                    "version": "5.2",
                    "status": "affected",
                    "lessThanOrEqual": "5.2",
                    "versionType": "custom"
                }

            ]
        }
    ],
    "signature_tokens": [
        "CVE-2020-10135",
        "Bluetooth",
        "EDR",
        "BIAS",
        "Legacy",
        "pairing",
        "secure-connections",
        "authentication",
        "Core",
        "Specification",
        "v5.2",
        "earlier",
        "allow",
        "unauthenticated",
        "user",
        "complete",
        "without",
        "credentials",
        "adjacent",
        "access",
        "could",
        "impersonate",
        "master",
        "slave",
        "pair",
        "BR/EDR"
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

class Poc62CVE202010135AuthBypassAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-077'
    meta_poc_name = 'CVE-2020-10135 认证绕过 Active Validation'
    meta_cve_id = 'CVE-2020-10135'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2020-10135'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2020-10135']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "62_BT_BIAS_Auth_Bypass_Audit") if "VULN" in dir() else "62_BT_BIAS_Auth_Bypass_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc62CVE202010135AuthBypassAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

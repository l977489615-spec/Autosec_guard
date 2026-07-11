#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


def _check_ble_environment() -> dict:
    """Check BLE environment for passkey MITM vulnerability assessment."""
    info = {
        "bluez_version": "",
        "ble_adapter": False,
        "potentially_vulnerable": None,
    }
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
            # CVE-2020-26558 BLE passkey MITM, fixed in BlueZ 5.55+
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

    # Check for BLE adapter
    try:
        r = subprocess.run(
            ["hcitool", "dev"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            if line.strip().startswith("hci"):
                info["ble_adapter"] = True
                break
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return info


def _probe_ble_pairing_exposure(mac: str) -> dict:
    """Check if BLE device is pairable and uses Passkey Entry method."""
    info = {"pairable": False, "io_capabilities": "", "error": ""}
    try:
        # Use bluetoothctl to check device pairing info
        r = subprocess.run(
            ["bluetoothctl", "info", mac],
            capture_output=True, text=True, timeout=10,
        )
        output = r.stdout + r.stderr
        info["device_info"] = output[:500]
        if "Paired: no" in output or "Paired:" in output:
            info["pairable"] = True
        # Check IO capability hint
        for line in output.splitlines():
            if "Class" in line or "Appearance" in line:
                info["io_capabilities"] = line.strip()
    except FileNotFoundError:
        info["error"] = "bluetoothctl not found"
    except subprocess.TimeoutExpired:
        info["error"] = "timeout"
    except Exception as exc:
        info["error"] = str(exc)
    return info


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    bt_mac = params.get("bluetooth_mac") or params.get("bt_mac", "")

    evidence = {
        "cve": "CVE-2020-26558",
        "target": bt_mac or "BLE device (Passkey Entry pairing MITM)",
        "technique": (
            "BLE Passkey Entry MITM audit: check BlueZ version, verify BLE adapter, "
            "probe device IO capability for Passkey Entry method exposure"
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-26558",
        "vuln_detail": (
            "BLE Passkey Entry MITM: attacker in middle can observe Passkey Entry values "
            "exchanged during pairing, enabling MITM without user detection."
        ),
        "attack_scenario": (
            "1. Position BLE-capable adapter between victim and target device\n"
            "2. Intercept Passkey Entry pairing using passive BLE sniffer\n"
            "3. Extract 6-digit passkey from observed pairing messages\n"
            "4. Use passkey to establish authenticated BLE connection"
        ),
    }

    ble_info = _check_ble_environment()
    evidence["ble_environment"] = ble_info

    if bt_mac and ble_info.get("ble_adapter"):
        pairing_info = _probe_ble_pairing_exposure(bt_mac)
        evidence["pairing_probe"] = pairing_info

    if ble_info.get("potentially_vulnerable") is True:
        vulnerable = True
        evidence["note"] = (
            f"BlueZ {ble_info['bluez_version']} is in BLE Passkey MITM vulnerable range (< 5.55). "
            "CVE-2020-26558 Passkey Entry MITM applicable."
        )
    elif ble_info.get("potentially_vulnerable") is False:
        vulnerable = False
        evidence["note"] = "BlueZ version appears patched for BLE Passkey MITM"
    else:
        vulnerable = None
        evidence["note"] = (
            "Cannot determine BLE Passkey MITM exposure. "
            "Requires BLE sniffer (Ubertooth/Bluetooth adapter) and target within BLE range."
        )

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


VULN = {
    "id": 79,
    "cve": "CVE-2020-26558",
    "year": 2020,
    "domain": "蓝牙/协议",
    "vendor_product": "Bluetooth LE",
    "component": "Passkey Entry",
    "type": "配对绕过/中间人",
    "summary": "BLE配对过程可被中间人/冒充影响。",
    "source_description": "Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication procedure) by reflection of the public key and the authentication evidence of the initiating device, potentially permitting this attacker to complete authenticated pairing with the responding device using the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit at a time.",
    "poc_status": "有公开研究/PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-26558",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-26558",
        "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/reporting-security/",
        "https://kb.cert.org/vuls/id/799380",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NSS6CTGE4UGTJLCOZOASDR3T3SLL6QJZ/",
        "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00520.html",
        "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00517.html",
        "https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html",
        "https://lists.debian.org/debian-lts-announce/2021/06/msg00019.html",
        "https://lists.debian.org/debian-lts-announce/2021/06/msg00022.html",
        "https://www.debian.org/security/2021/dsa-4951",
        "https://security.gentoo.org/glsa/202209-16",
        "https://cveawg.mitre.org/api/cve/CVE-2020-26558"
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
        "CVE-2020-26558",
        "Bluetooth",
        "Passkey",
        "Entry",
        "secure",
        "pairing",
        "Core",
        "Specification",
        "permit",
        "nearby",
        "man-in-the-middle",
        "identify",
        "used",
        "during",
        "authentication",
        "procedure",
        "reflection",
        "public",
        "evidence",
        "initiating",
        "device",
        "potentially",
        "permitting",
        "complete"
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

class Poc64CVE202026558ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-064"
    meta_poc_name = 'CVE-2020-26558 中间人 Active Validation'
    meta_cve_id = 'CVE-2020-26558'
    meta_severity = 'High'
    meta_protocol = 'bluetooth'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['bluetooth']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2020-26558'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2020-26558']
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "64_BLE_Passkey_Pairing_MITM_Audit") if "VULN" in dir() else "64_BLE_Passkey_Pairing_MITM_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc64CVE202026558ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

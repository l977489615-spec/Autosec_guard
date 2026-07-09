#!/usr/bin/env python3
"""
PoC Name: BLUFFS Session Key Downgrade
CVE: CVE-2023-24023
Component: Wireless Stack
Category: Wireless
Severity: High
CVSS: 6.8
Description: 强制Bluetooth BR/EDR协商最短密钥(entropy=1)
Prerequisites: Bluetooth适配器, 目标设备可达。
Usage: python3 10_CVE_2023_24023_BT_BLUFFS_Key_Downgrade_Active_Validation.py <target_mac>
"""
from __future__ import annotations

import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin
VULN = {
    "id":             0,
    "cve":            "CVE-2023-24023",
    "year":           2023,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "BT BLUFFS Key Downgrade",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2023-24023",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2023-24023"],
    "signature_tokens": ["CVE-2023-24023"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2023-24023 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2023-24023") if vuln else "CVE-2023-24023",
        "target":    getattr(plugin, "target_ip", "unknown"),
        "technique": "legacy exploit() wrapper",
        "raw":       str(result)[:300],
    }

    # 根据是否有主动网络调用推断等级
    level = "B" if vulnerable is True else ("C" if vulnerable is False else "D")
    try:
        from probe_utils import detection_confidence as _detection_confidence
        return _detection_confidence(level, evidence, vulnerable=vulnerable)
    except ImportError:
        return {
            "detection_confidence": {
                "level": level, "vulnerable": vulnerable,
                "evidence": evidence, "method": "legacy_wrapper",
            }
        }


class BLUFFSPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-010"
    meta_poc_name = 'CVE-2023-24023 BT BLUFFS Key Downgrade Active Validation'
    meta_cve_id = "CVE-2023-24023"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2023-24023"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2023-24023']
    meta_severity = "High"
    meta_protocol = "bluetooth"
    meta_profiles = ["bluetooth"]
    meta_target_os = ["all"]
    meta_required_params = ["bd_addr"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.params.get("bd_addr"):
            raise RuntimeError("需要指定目标蓝牙MAC地址 (bd_addr)")
        return True
    def exploit(self):
        target = self.params["bd_addr"]
        self.logger.info(f"BLUFFS会话密钥降级测试: {target}")
        self.logger.info("CVE-2023-24023: 强制Bluetooth BR/EDR协商短密钥")
        try:
            # Attempt L2CAP connection to check if device is reachable
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
            s.settimeout(5)
            s.connect((target, 1))
            self.logger.info("[+] L2CAP连接成功")
            # In real exploit: intercept LMP during pairing, force entropy=1
            self.logger.info("[*] 实际攻击需要在配对过程中拦截LMP包并强制entropy=1")
            self.logger.info("[*] 这需要修改的蓝牙固件或自定义HCI设备")
            # Check BT version via SDP for vulnerability
            self.logger.warning("[*] 设备可达，但 BLUFFS 仍需在真实配对流程中验证是否接受降级密钥。")
            self.results["vulnerable"] = False
            self.results["evidence"] = f"L2CAP connection to {target} succeeded; key downgrade not yet demonstrated."
            s.close()
        except Exception as e:
            self.logger.info(f"蓝牙连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 10_CVE_2023_24023_BT_BLUFFS_Key_Downgrade_Active_Validation.py <target_mac>")
        sys.exit(1)
    plugin = BLUFFSPlugin({"target_ip": "N/A", "bd_addr": sys.argv[1]})
    plugin.run_verify()

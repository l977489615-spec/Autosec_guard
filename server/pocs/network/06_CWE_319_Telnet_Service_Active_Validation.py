#!/usr/bin/env python3
"""
PoC Name: Telnet Service Detection
Identifier: CWE-319
Component: Network Stack
Category: Network
Severity: High
CVSS: 7.5
Description: 检测Telnet服务是否开放(明文传输风险)
Prerequisites: 目标Telnet端口(23)开放。
Usage: python3 06_CWE_319_Telnet_Service_Active_Validation.py <target_ip>
"""
from __future__ import annotations

import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-319",
    "year":           319,
    "domain":         "network",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "Telnet Service",
    "source_url":     "https://cwe.mitre.org/data/definitions/319.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/319.html"],
    "signature_tokens": ["CWE-319"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-319 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-319") if vuln else "CWE-319",
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


class TelnetServicePlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-006"
    meta_poc_name = 'CWE-319 Telnet Service Active Validation'
    meta_cve_id = "CWE-319"
    meta_source_url = "https://cwe.mitre.org/data/definitions/319.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/319.html']
    meta_severity = "High"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles = ["network"]
    meta_grants_on_confirmed = ["service:telnet"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        port = 23
        self.logger.info(f"检测Telnet服务 {self.target_ip}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            if s.connect_ex((self.target_ip, port)) != 0:
                self.logger.info("Telnet端口23关闭")
                self.results["vulnerable"] = False
                s.close()
                return self.results
            self.logger.warning("[+] Telnet端口23开放！明文协议存在安全风险")
            try:
                banner = s.recv(1024).decode('ascii', 'ignore').strip()
                if banner:
                    self.logger.info(f"Banner: {banner[:200]}")
                    self.results["evidence"] = f"Telnet banner: {banner[:100]}"
            except:
                pass
            s.close()
            self.results["vulnerable"] = True
        except Exception as e:
            self.logger.error(f"连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 06_CWE_319_Telnet_Service_Active_Validation.py <target_ip>")
        sys.exit(1)
    plugin = TelnetServicePlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

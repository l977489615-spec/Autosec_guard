#!/usr/bin/env python3
"""
PoC Name: HTTP Service Enumeration
Identifier: CWE-200
Component: Recon Stack
Category: Recon
Severity: Medium
CVSS: 5.0
Description: 扫描常见Web端口,获取Server信息
Prerequisites: 目标Web端口开放。
Usage: python3 08_CWE_200_HTTP_Service_Enumeration_Reconnaissance.py <target_ip>
"""
from __future__ import annotations

import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-200",
    "year":           200,
    "domain":         "reconnaissance",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "HTTP Service Enum",
    "source_url":     "https://cwe.mitre.org/data/definitions/200.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/200.html"],
    "signature_tokens": ["CWE-200"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-200 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-200") if vuln else "CWE-200",
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


class HTTPServiceEnumPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-RECON-008"
    meta_poc_name = 'CWE-200 HTTP Service 枚举 Reconnaissance'
    meta_cve_id = "CWE-200"
    meta_source_url = "https://cwe.mitre.org/data/definitions/200.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/200.html']
    meta_severity = "Medium"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles         = ["recon"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    PORTS = [80, 443, 8080, 8443, 8888, 3000, 4040, 9090]

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        self.logger.info(f"扫描Web端口 {self.target_ip}...")
        found_any = False
        for port in self.PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((self.target_ip, port)) == 0:
                    self.logger.warning(f"[+] 端口 {port} 开放")
                    found_any = True
                    try:
                        req = f"HEAD / HTTP/1.0\r\nHost: {self.target_ip}\r\n\r\n"
                        s.send(req.encode())
                        resp = s.recv(1024).decode('utf-8', 'ignore')
                        for line in resp.split("\r\n"):
                            if line.lower().startswith("server:"):
                                self.logger.info(f"    Server: {line}")
                                self.results["evidence"] = line
                    except:
                        pass
                s.close()
            except:
                pass
        self.results["vulnerable"] = found_any
        if not found_any:
            self.logger.info("未发现开放的Web端口")
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 08_CWE_200_HTTP_Service_Enumeration_Reconnaissance.py <target_ip>")
        sys.exit(1)
    plugin = HTTPServiceEnumPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

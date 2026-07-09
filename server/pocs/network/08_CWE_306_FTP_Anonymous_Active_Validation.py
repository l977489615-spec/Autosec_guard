#!/usr/bin/env python3
"""
PoC Name: FTP Anonymous Login
Identifier: CWE-306
Component: Network Stack
Category: Network
Severity: High
CVSS: 7.5
Description: 检测FTP服务是否允许匿名登录
Prerequisites: 目标FTP端口(21)开放。
Usage: python3 08_CWE_306_FTP_Anonymous_Active_Validation.py <target_ip>
"""
from __future__ import annotations

import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-306",
    "year":           306,
    "domain":         "network",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "FTP Anonymous",
    "source_url":     "https://cwe.mitre.org/data/definitions/306.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/306.html"],
    "signature_tokens": ["CWE-306"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-306 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-306") if vuln else "CWE-306",
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


class FTPAnonymousPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-008"
    meta_poc_name = 'CWE-306 FTP Anonymous Active Validation'
    meta_cve_id = "CWE-306"
    meta_source_url = "https://cwe.mitre.org/data/definitions/306.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/306.html']
    meta_severity = "High"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles = ["network"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        port = 21
        self.logger.info(f"检测FTP匿名登录 {self.target_ip}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            if s.connect_ex((self.target_ip, port)) != 0:
                self.logger.info("FTP端口21关闭")
                self.results["vulnerable"] = False
                s.close()
                return self.results
            banner = s.recv(1024).decode('utf-8', 'ignore').strip()
            self.logger.info(f"FTP Banner: {banner}")
            s.send(b"USER anonymous\r\n")
            resp = s.recv(1024).decode('utf-8', 'ignore')
            if "331" in resp:
                s.send(b"PASS anonymous@\r\n")
                resp2 = s.recv(1024).decode('utf-8', 'ignore')
                if "230" in resp2:
                    self.logger.warning("[+] FTP匿名登录成功！")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = "FTP anonymous login accepted"
                else:
                    self.logger.info("匿名登录被拒绝")
                    self.results["vulnerable"] = False
            else:
                self.results["vulnerable"] = False
            s.close()
        except Exception as e:
            self.logger.error(f"连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 08_CWE_306_FTP_Anonymous_Active_Validation.py <target_ip>")
        sys.exit(1)
    plugin = FTPAnonymousPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

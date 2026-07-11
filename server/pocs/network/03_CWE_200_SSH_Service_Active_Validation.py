#!/usr/bin/env python3
"""
PoC Name: SSH Service Detection
Identifier: CWE-200
Component: Network Stack
Category: Network
Severity: Medium
CVSS: 5.0
Description: 检测SSH服务是否开放(潜在攻击面点)
Prerequisites: 目标SSH端口(22)开放。
Usage: python3 03_CWE_200_SSH_Service_Active_Validation.py <target_ip>
"""
from __future__ import annotations

import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-200",
    "year":           200,
    "domain":         "network",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "SSH Service",
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


class SSHServicePlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-003"
    meta_poc_name = 'CWE-200 SSH Service Active Validation'
    meta_cve_id = "CWE-200"
    meta_source_url = "https://cwe.mitre.org/data/definitions/200.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/200.html']
    meta_severity = "Medium"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles = ["network"]
    meta_grants_on_confirmed = ["service:ssh"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        port = 22
        self.logger.info(f"检测SSH服务 {self.target_ip}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            if s.connect_ex((self.target_ip, port)) != 0:
                self.logger.info("SSH端口22关闭")
                self.results["vulnerable"] = False
                s.close()
                return self.results
            
            self.logger.warning("[+] SSH端口22开放！")
            try:
                banner = s.recv(1024).decode('ascii', 'ignore').strip()
                if banner:
                    self.logger.info(f"Banner: {banner[:200]}")
                    self.results["evidence"] = f"SSH banner: {banner[:100]}"
            except:
                pass
            s.close()
            # 根据UN R155/ISO 21434, 暴露非必要的管理服务可被视为风险
            self.results["vulnerable"] = True
            
        except Exception as e:
            self.logger.error(f"连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 03_CWE_200_SSH_Service_Active_Validation.py <target_ip>")
        sys.exit(1)
    plugin = SSHServicePlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

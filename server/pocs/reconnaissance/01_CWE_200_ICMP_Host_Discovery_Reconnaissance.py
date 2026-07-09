#!/usr/bin/env python3
"""
PoC Name: ICMP Host Discovery
Identifier: CWE-200
Component: Recon Stack
Category: Recon
Severity: Low
CVSS: 0.0
Description: ICMP Ping检测目标主机是否在线
Prerequisites: 网络可达性,可能需要root权限发送原始ICMP包。
Usage: python3 01_CWE_200_ICMP_Host_Discovery_Reconnaissance.py <target_ip>
"""
from __future__ import annotations

import subprocess
import sys
import platform
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-200",
    "year":           200,
    "domain":         "reconnaissance",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "ICMP Host Discovery",
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


class ICMPHostDiscoveryPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-RECON-001"
    meta_poc_name = 'CWE-200 ICMP 主机发现 Reconnaissance'
    meta_cve_id = "CWE-200"
    meta_source_url = "https://cwe.mitre.org/data/definitions/200.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/200.html']
    meta_severity = "Low"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles         = ["recon"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        self.logger.info(f"ICMP Ping检测 {self.target_ip}...")
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            result = subprocess.run(
                ["ping", param, "3", "-W", "2", self.target_ip],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self.logger.info(f"[+] 主机 {self.target_ip} 在线")
                for line in result.stdout.splitlines():
                    if "ttl" in line.lower() or "time" in line.lower():
                        self.logger.info(f"    {line.strip()}")
                self.results["vulnerable"] = True
                self.results["evidence"] = "Host responds to ICMP"
            else:
                self.logger.info(f"[-] 主机 {self.target_ip} 未响应ICMP")
                self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"Ping失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 01_CWE_200_ICMP_Host_Discovery_Reconnaissance.py <target_ip>")
        sys.exit(1)
    plugin = ICMPHostDiscoveryPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

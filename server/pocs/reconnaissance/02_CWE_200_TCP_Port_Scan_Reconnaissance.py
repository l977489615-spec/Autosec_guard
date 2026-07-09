#!/usr/bin/env python3
"""
PoC Name: TCP Port Scan
Identifier: CWE-200
Component: Recon Stack
Category: Recon
Severity: Medium
CVSS: 5.0
Description: 扫描IVI系统Top-50常见TCP端口
Prerequisites: 网络可达性。
Usage: python3 02_CWE_200_TCP_Port_Scan_Reconnaissance.py <target_ip>
"""
from __future__ import annotations

import socket
import sys
import time
import re
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-200",
    "year":           200,
    "domain":         "reconnaissance",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "TCP Port Scan",
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


class TCPPortScanPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-RECON-002"
    meta_poc_name = 'CWE-200 TCP 端口扫描 Reconnaissance'
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

    TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 3804,
        5555, 5900, 6667, 7000, 8000, 8080, 8443, 8888,
        9090, 9200, 27017, 1900, 5353, 554, 1883, 6379,
        4444, 5000, 5555, 6000, 8081, 9000, 10000,
        13400, 30490, 49152, 49153, 49154, 2049, 4040,
        55555, 61616, 11211
    ]

    def _scan_ports(self):
        candidate_ports = self.params.get("candidate_ports")
        if isinstance(candidate_ports, list):
            ports = [int(port) for port in candidate_ports if str(port).isdigit()]
        elif candidate_ports:
            ports = [
                int(part)
                for part in re.split(r"[,;\s]+", str(candidate_ports).strip())
                if part.isdigit()
            ]
        else:
            ports = []
        return sorted(set(ports or self.TOP_PORTS))

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        scan_ports = self._scan_ports()
        self.logger.info(f"扫描 {self.target_ip} 候选端口: {scan_ports}")
        open_ports = []
        for port in scan_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((self.target_ip, port)) == 0:
                    open_ports.append(port)
                    self.logger.warning(f"[+] {port}/tcp OPEN")
                s.close()
            except:
                pass
        if open_ports:
            self.results["vulnerable"] = True
            self.results["evidence"] = f"Open ports: {open_ports}"
            self.logger.info(f"共发现 {len(open_ports)} 个开放端口")
        else:
            self.results["vulnerable"] = False
            self.logger.info("未发现开放端口")
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 02_CWE_200_TCP_Port_Scan_Reconnaissance.py <target_ip>")
        sys.exit(1)
    plugin = TCPPortScanPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

#!/usr/bin/env python3
"""
PoC Name: mDNS Service Discovery
Identifier: CWE-200
Component: Recon Stack
Category: Recon
Severity: Low
CVSS: 3.0
Description: 通过mDNS多播查询发现AirPlay/CarPlay/DLNA等服务
Prerequisites: 与目标同一网段。
Usage: python3 03_CWE_200_Service_Discovery_Reconnaissance.py <target_ip>
"""
from __future__ import annotations

import socket
import struct
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-200",
    "year":           200,
    "domain":         "reconnaissance",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "mDNS Service Discovery",
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


class mDNSDiscoveryPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-RECON-003"
    meta_poc_name = 'CWE-200 服务发现 Reconnaissance'
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
        return True

    def exploit(self):
        self.logger.info("发送mDNS查询 (_services._dns-sd._udp.local)...")
        MDNS_ADDR = "224.0.0.251"
        MDNS_PORT = 5353
        # Build DNS query for _services._dns-sd._udp.local
        query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        query += b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        query += b"\x00\x0c\x00\x01"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
            services = []
            start = time.time()
            while time.time() - start < 3:
                try:
                    data, addr = sock.recvfrom(4096)
                    if addr[0] == self.target_ip or not self.target_ip:
                        self.logger.info(f"[+] mDNS响应来自 {addr[0]} ({len(data)} bytes)")
                        services.append(addr[0])
                except socket.timeout:
                    break
            sock.close()
            if services:
                self.results["vulnerable"] = True
                self.results["evidence"] = f"mDNS services found from: {services}"
            else:
                self.logger.info("未发现mDNS服务")
                self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"mDNS查询失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 03_CWE_200_Service_Discovery_Reconnaissance.py <target_ip>")
        sys.exit(1)
    plugin = mDNSDiscoveryPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

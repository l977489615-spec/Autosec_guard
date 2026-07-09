#!/usr/bin/env python3
"""
PoC Name: SNMP Community String Check
Identifier: CWE-798
Component: Recon Stack
Category: Recon
Severity: Medium
CVSS: 5.5
Description: 检测SNMP服务是否使用默认community string
Prerequisites: 目标SNMP端口(161)开放。
Usage: python3 05_CWE_798_Leak_Reconnaissance.py <target_ip>
"""
from __future__ import annotations

import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-798",
    "year":           798,
    "domain":         "reconnaissance",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "SNMP Info Leak",
    "source_url":     "https://cwe.mitre.org/data/definitions/798.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/798.html"],
    "signature_tokens": ["CWE-798"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-798 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-798") if vuln else "CWE-798",
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


class SNMPInfoLeakPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-RECON-005"
    meta_poc_name = 'CWE-798 Leak Reconnaissance'
    meta_cve_id = "CWE-798"
    meta_source_url = "https://cwe.mitre.org/data/definitions/798.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/798.html']
    meta_severity = "Medium"
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

    def _build_snmp_get(self, community):
        # SNMPv1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)
        oid = b"\x30\x26\x02\x01\x00\x04"
        comm = community.encode()
        oid += bytes([len(comm)]) + comm
        oid += b"\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
        oid += b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
        return oid

    def exploit(self):
        port = 161
        self.logger.info(f"检测SNMP {self.target_ip}:{port}...")
        for community in ["public", "private", "community"]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                pkt = self._build_snmp_get(community)
                sock.sendto(pkt, (self.target_ip, port))
                data, _ = sock.recvfrom(4096)
                if len(data) > 10:
                    self.logger.warning(f"[+] SNMP community string '{community}' 有效！({len(data)} bytes)")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"SNMP community: {community}"
                    sock.close()
                    return self.results
                sock.close()
            except socket.timeout:
                continue
            except Exception:
                continue
        self.logger.info("SNMP未响应或默认community无效")
        self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 05_CWE_798_Leak_Reconnaissance.py <target_ip>")
        sys.exit(1)
    plugin = SNMPInfoLeakPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

#!/usr/bin/env python3
"""
PoC Name: UPnP/SSDP Discovery
Identifier: CWE-200
Component: Recon Stack
Category: Recon
Severity: Low
CVSS: 3.0
Description: 通过SSDP M-SEARCH广播发现UPnP设备
Prerequisites: 与目标同一网段。
Usage: python3 04_CWE_200_UPnP_SSDP_Discovery_Reconnaissance.py <target_ip>
"""
from __future__ import annotations

import socket
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
    "summary":        "UPnP SSDP Discovery",
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


class UPnPSSDPPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-RECON-004"
    meta_poc_name = 'CWE-200 UPnP SSDP Discovery Reconnaissance'
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
        self.logger.info("发送SSDP M-SEARCH广播...")
        msg = "\r\n".join([
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            "MX: 2",
            "ST: ssdp:all",
            "", ""
        ]).encode()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(msg, ("239.255.255.250", 1900))
            devices = []
            start = time.time()
            while time.time() - start < 4:
                try:
                    data, addr = sock.recvfrom(4096)
                    if self.target_ip and addr[0] != self.target_ip:
                        continue
                    text = data.decode("utf-8", "ignore")
                    location = ""
                    server = ""
                    for line in text.split("\r\n"):
                        if line.upper().startswith("LOCATION:"):
                            location = line.split(":", 1)[1].strip()
                        if line.upper().startswith("SERVER:"):
                            server = line.split(":", 1)[1].strip()
                    if location:
                        self.logger.info(f"[+] UPnP设备 {addr[0]}: {server} -> {location}")
                        devices.append({"ip": addr[0], "location": location, "server": server})
                except socket.timeout:
                    break
            sock.close()
            if devices:
                self.results["vulnerable"] = True
                self.results["evidence"] = f"Found {len(devices)} UPnP devices"
            else:
                self.logger.info("未发现UPnP设备")
                self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"SSDP发现失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 04_CWE_200_UPnP_SSDP_Discovery_Reconnaissance.py <target_ip>")
        sys.exit(1)
    plugin = UPnPSSDPPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

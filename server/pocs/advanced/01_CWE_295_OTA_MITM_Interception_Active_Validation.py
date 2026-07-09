#!/usr/bin/env python3
"""
PoC Name: OTA Update MITM Interception
Identifier: CWE-295
Component: Multiple
Category: Advanced
Severity: Critical
CVSS: 8.5
Description: 检测OTA更新通道是否使用自签名证书(MITM风险)
Prerequisites: 与目标同一网络。
Usage: python3 01_CWE_295_OTA_MITM_Interception_Active_Validation.py <target_ip>
"""
from __future__ import annotations

import socket
import ssl
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
VULN = {
    "id":             0,
    "cve":            "CWE-295",
    "year":           295,
    "domain":         "advanced",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "OTA MITM Interception",
    "source_url":     "https://cwe.mitre.org/data/definitions/295.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/295.html"],
    "signature_tokens": ["CWE-295"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-295 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-295") if vuln else "CWE-295",
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


class OTAMITMPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-ADV-001"
    meta_poc_name = 'CWE-295 OTA MITM Interception Active Validation'
    meta_cve_id = "CWE-295"
    meta_source_url = "https://cwe.mitre.org/data/definitions/295.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/295.html']
    meta_severity = "Critical"
    meta_protocol = "https"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles = ["advanced_network"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    OTA_PORTS = [443, 8443, 4443, 9443]
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址")
        return True
    def exploit(self):
        self.logger.info(f"OTA MITM测试 {self.target_ip}")
        self.logger.info("检测HTTPS证书验证强度...")
        for port in self.OTA_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((self.target_ip, port)) != 0:
                    s.close()
                    continue
                s.close()
                # Try connecting with unverified SSL
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ctx.wrap_socket(socket.socket(), server_hostname=self.target_ip)
                conn.settimeout(5)
                conn.connect((self.target_ip, port))
                cert = conn.getpeercert(binary_form=True)
                self.logger.info(f"[+] TLS连接端口 {port} (证书 {len(cert)}B)")
                # Check if self-signed or weak
                try:
                    ctx2 = ssl.create_default_context()
                    conn2 = ctx2.wrap_socket(socket.socket(), server_hostname=self.target_ip)
                    conn2.settimeout(5)
                    conn2.connect((self.target_ip, port))
                    conn2.close()
                    self.logger.info(f"  证书验证通过 - 使用有效CA证书")
                except ssl.SSLCertVerificationError:
                    self.logger.warning(f"[+] 端口 {port} 使用自签名证书！MITM风险")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"Self-signed cert on port {port}"
                conn.close()
                if self.results.get("vulnerable"):
                    return self.results
            except Exception as e:
                continue
        if not self.results.get("vulnerable"):
            self.logger.info("[-] 未发现TLS配置弱点")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 01_CWE_295_OTA_MITM_Interception_Active_Validation.py <target_ip>")
        sys.exit(1)
    plugin = OTAMITMPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

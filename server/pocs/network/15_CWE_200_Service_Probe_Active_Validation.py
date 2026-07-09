#!/usr/bin/env python3
"""
PoC Name: Dynamic Unknown Service Probe
Identifier: CWE-200
Component: Unknown Network Service
Category: Network
Severity: Medium
Description: Weaponize Agent 生成的协议感知型未知服务动态探测脚本
Prerequisites: 目标可达
"""
from __future__ import annotations

import sys
import socket
import time
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id":             0,
    "cve":            "CWE-200",
    "year":           200,
    "domain":         "network",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "Dynamic Unknown Service Probe",
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


class DynamicUnknownServiceProbePlugin(IVIVulnerabilityPlugin):
    meta_display_id       = "POC-NET-015"
    meta_poc_name = 'CWE-200 Service Probe Active Validation'
    meta_cve_id = "CWE-200"
    meta_source_url = "https://cwe.mitre.org/data/definitions/200.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/200.html']
    meta_severity = "Medium"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles         = ["network"]
    is_disruptive = False
    meta_destructive_level = "Probe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        self.results["description"] = "未知服务动态指纹与异常响应探测"
        target_ip = self.target_ip
        target_port = self.target_port
        try:
            import socket
            import struct
            import time
            import random

            # 目标IP地址
            TARGET_IP = "192.168.31.158"
            # 目标端口范围
            PORT_RANGE = (1, 65535)
            # 探测次数
            PROBE_COUNT = 10
            # 延迟时间（秒）
            DELAY = 0.1

            def create_socket():
                """创建一个原始套接字"""
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    return s
                except socket.error as msg:
                    print(f"Socket creation error: {msg}")
                    return None

            def send_probe(s, target_ip, port):
                """发送探测包"""
                ip_header = struct.pack('!BBHHHBBH4s4s',
                                        69,  # Version, IHL
                                        0,   # DSCP, ECN
                                        20 + 8,  # Total Length
                                        0,   # Identification
                                        0,   # Flags, Fragment Offset
                                        64,  # TTL
                                        6,   # Protocol (TCP)
                                        0,   # Header Checksum
                                        socket.inet_aton(target_ip),  # Source IP
                                        socket.inet_aton(target_ip))  # Destination IP

                tcp_header = struct.pack('!HHLLBBHHH',
                                         port,  # Source Port
                                         80,    # Destination Port
                                         0,     # Sequence Number
                                         0,     # Acknowledgment Number
                                         5 << 4,  # Data Offset, Reserved, Flags
                                         2,     # Window Size
                                         0,     # Checksum
                                         0)     # Urgent Pointer

                packet = ip_header + tcp_header
                s.sendto(packet, (target_ip, 0))

            def receive_response(s, timeout=1):
                """接收响应包"""
                s.settimeout(timeout)
                try:
                    response, addr = s.recvfrom(65535)
                    return response
                except socket.timeout:
                    return None

            def main():
                s = create_socket()
                if not s:
                    return

                normal_responses = []
                for _ in range(PROBE_COUNT):
                    port = random.randint(*PORT_RANGE)
                    send_probe(s, TARGET_IP, port)
                    time.sleep(DELAY)
                    response = receive_response(s)
                    if response:
                        normal_responses.append(response)
                        print(f"Received response from port {port}")

                if not normal_responses:
                    print("No responses received. Target may be unreachable or silent.")
                    return

                # 建立正常响应基线
                baseline = set(normal_responses)

                # 收集异常证据
                vulnerable = False
                for _ in range(PROBE_COUNT):
                    port = random.randint(*PORT_RANGE)
                    send_probe(s, TARGET_IP, port)
                    time.sleep(DELAY)
                    response = receive_response(s)
                    if response and response not in baseline:
                        print(f"Abnormal response received from port {port}")
                        vulnerable = True
                        break

                if vulnerable:
                    print("Vulnerable: True")
                else:
                    print("Vulnerable: False")

                s.close()
        except Exception as e:
            self.logger.error(f"动态未知服务探测脚本执行异常: {e}")
            self.results["vulnerable"] = False
            self.results["evidence"] = f"Exception: {e}"
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 network/15_CWE_200_Service_Probe_Active_Validation.py <target_ip>")
        sys.exit(1)
    plugin = DynamicUnknownServiceProbePlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

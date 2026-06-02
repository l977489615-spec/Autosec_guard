"""
PoC Name: FTP Anonymous Login
CVE: N/A
Component: Network Stack
Category: Network
Severity: High
CVSS: 7.5
Description: 检测FTP服务是否允许匿名登录
Prerequisites: 目标FTP端口(21)开放。
Usage: python3 08_FTP_Anonymous.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class FTPAnonymousPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-008"
    meta_poc_name = "FTP Anonymous"
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
        port = 21
        self.logger.info(f"检测FTP匿名登录 {self.target_ip}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            if s.connect_ex((self.target_ip, port)) != 0:
                self.logger.info("FTP端口21关闭")
                self.results["vulnerable"] = False
                s.close()
                return self.results
            banner = s.recv(1024).decode('utf-8', 'ignore').strip()
            self.logger.info(f"FTP Banner: {banner}")
            s.send(b"USER anonymous\r\n")
            resp = s.recv(1024).decode('utf-8', 'ignore')
            if "331" in resp:
                s.send(b"PASS anonymous@\r\n")
                resp2 = s.recv(1024).decode('utf-8', 'ignore')
                if "230" in resp2:
                    self.logger.warning("[+] FTP匿名登录成功！")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = "FTP anonymous login accepted"
                else:
                    self.logger.info("匿名登录被拒绝")
                    self.results["vulnerable"] = False
            else:
                self.results["vulnerable"] = False
            s.close()
        except Exception as e:
            self.logger.error(f"连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 08_FTP_Anonymous.py <target_ip>")
        sys.exit(1)
    plugin = FTPAnonymousPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

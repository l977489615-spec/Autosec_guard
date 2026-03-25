"""
PoC Name: SSH Service Detection
CVE: N/A
Component: Network Stack
Category: Network
Severity: Medium
CVSS: 5.0
Description: 检测SSH服务是否开放(潜在攻击面点)
Prerequisites: 目标SSH端口(22)开放。
Usage: python3 10_SSH_Service.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class SSHServicePlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        port = 22
        self.logger.info(f"检测SSH服务 {self.target_ip}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            if s.connect_ex((self.target_ip, port)) != 0:
                self.logger.info("SSH端口22关闭")
                self.results["vulnerable"] = False
                s.close()
                return self.results
            
            self.logger.warning("[+] SSH端口22开放！")
            try:
                banner = s.recv(1024).decode('ascii', 'ignore').strip()
                if banner:
                    self.logger.info(f"Banner: {banner[:200]}")
                    self.results["evidence"] = f"SSH banner: {banner[:100]}"
            except:
                pass
            s.close()
            # 根据UN R155/ISO 21434, 暴露非必要的管理服务可被视为风险
            self.results["vulnerable"] = True
            
        except Exception as e:
            self.logger.error(f"连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 10_SSH_Service.py <target_ip>")
        sys.exit(1)
    plugin = SSHServicePlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

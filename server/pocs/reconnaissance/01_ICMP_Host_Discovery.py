"""
PoC Name: ICMP Host Discovery
Identifier: CWE-200
Component: Recon Stack
Category: Recon
Severity: Low
CVSS: 0.0
Description: ICMP Ping检测目标主机是否在线
Prerequisites: 网络可达性,可能需要root权限发送原始ICMP包。
Usage: python3 01_ICMP_Host_Discovery.py <target_ip>
"""
import subprocess
import sys
import platform
from iv_plugin_base import IVIVulnerabilityPlugin

class ICMPHostDiscoveryPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-RECON-001"
    meta_poc_name = "ICMP Host Discovery"
    meta_cve_id = "CWE-200"
    meta_severity = "Low"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        self.logger.info(f"ICMP Ping检测 {self.target_ip}...")
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            result = subprocess.run(
                ["ping", param, "3", "-W", "2", self.target_ip],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self.logger.info(f"[+] 主机 {self.target_ip} 在线")
                for line in result.stdout.splitlines():
                    if "ttl" in line.lower() or "time" in line.lower():
                        self.logger.info(f"    {line.strip()}")
                self.results["vulnerable"] = True
                self.results["evidence"] = "Host responds to ICMP"
            else:
                self.logger.info(f"[-] 主机 {self.target_ip} 未响应ICMP")
                self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"Ping失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 01_ICMP_Host_Discovery.py <target_ip>")
        sys.exit(1)
    plugin = ICMPHostDiscoveryPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

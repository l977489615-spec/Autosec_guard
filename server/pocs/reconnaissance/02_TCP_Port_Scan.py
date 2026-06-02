"""
PoC Name: TCP Port Scan
CVE: N/A
Component: Recon Stack
Category: Recon
Severity: Medium
CVSS: 5.0
Description: 扫描IVI系统Top-50常见TCP端口
Prerequisites: 网络可达性。
Usage: python3 02_TCP_Port_Scan.py <target_ip>
"""
import socket
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

class TCPPortScanPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-RECON-002"
    meta_poc_name = "TCP Port Scan"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 3804,
        5555, 5900, 6667, 7000, 8000, 8080, 8443, 8888,
        9090, 9200, 27017, 1900, 5353, 554, 1883, 6379,
        4444, 5000, 5555, 6000, 8081, 9000, 10000,
        49152, 49153, 49154, 2049, 4040, 55555, 61616, 11211
    ]

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        self.logger.info(f"扫描 {self.target_ip} Top-50端口...")
        open_ports = []
        for port in sorted(set(self.TOP_PORTS)):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((self.target_ip, port)) == 0:
                    open_ports.append(port)
                    self.logger.warning(f"[+] {port}/tcp OPEN")
                s.close()
            except:
                pass
        if open_ports:
            self.results["vulnerable"] = True
            self.results["evidence"] = f"Open ports: {open_ports}"
            self.logger.info(f"共发现 {len(open_ports)} 个开放端口")
        else:
            self.results["vulnerable"] = False
            self.logger.info("未发现开放端口")
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 02_TCP_Port_Scan.py <target_ip>")
        sys.exit(1)
    plugin = TCPPortScanPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

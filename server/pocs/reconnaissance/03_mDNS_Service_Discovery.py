"""
PoC Name: mDNS Service Discovery
CVE: N/A
Component: Recon Stack
Category: Recon
Severity: Low
CVSS: 3.0
Description: 通过mDNS多播查询发现AirPlay/CarPlay/DLNA等服务
Prerequisites: 与目标同一网段。
Usage: python3 03_mDNS_Service_Discovery.py <target_ip>
"""
import socket
import struct
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

class mDNSDiscoveryPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = "mDNS Service Discovery"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        self.logger.info("发送mDNS查询 (_services._dns-sd._udp.local)...")
        MDNS_ADDR = "224.0.0.251"
        MDNS_PORT = 5353
        # Build DNS query for _services._dns-sd._udp.local
        query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        query += b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        query += b"\x00\x0c\x00\x01"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
            services = []
            start = time.time()
            while time.time() - start < 3:
                try:
                    data, addr = sock.recvfrom(4096)
                    if addr[0] == self.target_ip or not self.target_ip:
                        self.logger.info(f"[+] mDNS响应来自 {addr[0]} ({len(data)} bytes)")
                        services.append(addr[0])
                except socket.timeout:
                    break
            sock.close()
            if services:
                self.results["vulnerable"] = True
                self.results["evidence"] = f"mDNS services found from: {services}"
            else:
                self.logger.info("未发现mDNS服务")
                self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"mDNS查询失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 03_mDNS_Service_Discovery.py <target_ip>")
        sys.exit(1)
    plugin = mDNSDiscoveryPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

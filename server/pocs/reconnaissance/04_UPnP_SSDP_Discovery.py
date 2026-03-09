"""
PoC Name: UPnP/SSDP Device Discovery
CVE: N/A
Component: UPnP/SSDP Protocol
Category: Recon
Severity: Low
CVSS: 3.0
Description: 通过SSDP M-SEARCH广播发现UPnP设备和服务。
Prerequisites: 与目标同一网段。
Usage: python3 35_UPnP_SSDP_Discovery.py <target_ip>
"""
import socket
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

class UPnPSSDPPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        return True

    def exploit(self):
        self.logger.info("发送SSDP M-SEARCH广播...")
        msg = "\r\n".join([
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            "MX: 2",
            "ST: ssdp:all",
            "", ""
        ]).encode()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(msg, ("239.255.255.250", 1900))
            devices = []
            start = time.time()
            while time.time() - start < 4:
                try:
                    data, addr = sock.recvfrom(4096)
                    if self.target_ip and addr[0] != self.target_ip:
                        continue
                    text = data.decode("utf-8", "ignore")
                    location = ""
                    server = ""
                    for line in text.split("\r\n"):
                        if line.upper().startswith("LOCATION:"):
                            location = line.split(":", 1)[1].strip()
                        if line.upper().startswith("SERVER:"):
                            server = line.split(":", 1)[1].strip()
                    if location:
                        self.logger.info(f"[+] UPnP设备 {addr[0]}: {server} -> {location}")
                        devices.append({"ip": addr[0], "location": location, "server": server})
                except socket.timeout:
                    break
            sock.close()
            if devices:
                self.results["vulnerable"] = True
                self.results["evidence"] = f"Found {len(devices)} UPnP devices"
            else:
                self.logger.info("未发现UPnP设备")
                self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"SSDP发现失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    plugin = UPnPSSDPPlugin({"target_ip": target})
    plugin.run_verify()

"""
PoC Name: N/A
CVE: N/A
Component: N/A
Category: N/A
Severity: N/A
CVSS: N/A
Description: N/A
Prerequisites: T-Box/TCU网络可达(通过4G/LTE APN或同网络)。
Usage: python3 07_TBox_Port_Scan.py <target_ip>
"""
import socket
import sys
import re
from iv_plugin_base import IVIVulnerabilityPlugin
class TBOXPortScanPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-RECON-007"
    meta_poc_name = "TBox Port Scan"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    TBOX_PORTS = {
        22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
        554: "RTSP", 1883: "MQTT", 8883: "MQTT-TLS",
        5555: "ADB", 6666: "Debug", 8080: "HTTP-Alt",
        9090: "Diagnostic", 6667: "D-Bus", 7000: "AirPlay/Ctrl",
        3804: "HiQnet", 5353: "mDNS", 61616: "ActiveMQ",
        1900: "SSDP", 8443: "HTTPS-Alt", 4840: "OPC-UA",
        502: "Modbus", 102: "S7comm", 13400: "DoIP",
        30490: "SOME/IP-SD"
    }

    def _scan_ports(self):
        candidate_ports = self.params.get("candidate_ports")
        if isinstance(candidate_ports, list):
            ports = [int(port) for port in candidate_ports if str(port).isdigit()]
        elif candidate_ports:
            ports = [
                int(part)
                for part in re.split(r"[,;\s]+", str(candidate_ports).strip())
                if part.isdigit()
            ]
        else:
            ports = []
        return sorted(set(ports or self.TBOX_PORTS.keys()))

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址")
        return True
    def exploit(self):
        scan_ports = self._scan_ports()
        self.logger.info(f"T-Box端口扫描 {self.target_ip} 候选端口: {scan_ports}")
        open_ports = []
        for port in scan_ports:
            name = self.TBOX_PORTS.get(port, f"tcp/{port}")
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                if s.connect_ex((self.target_ip, port)) == 0:
                    self.logger.warning(f"[+] {port}/tcp ({name}) OPEN")
                    open_ports.append((port, name))
                s.close()
            except:
                pass
        if open_ports:
            self.results["vulnerable"] = True
            self.results["evidence"] = f"Open: {[(p,n) for p,n in open_ports]}"
            self.logger.info(f"共发现 {len(open_ports)} 个开放端口")
        else:
            self.results["vulnerable"] = False
            self.logger.info("未发现开放端口")
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 07_TBox_Port_Scan.py <target_ip>")
        sys.exit(1)
    plugin = TBOXPortScanPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

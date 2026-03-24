"""
PoC Name: SNMP Community String Check
CVE: N/A
Component: Recon Stack
Category: Recon
Severity: Medium
CVSS: 5.5
Description: 检测SNMP服务是否使用默认community string
Prerequisites: 目标SNMP端口(161)开放。
Usage: python3 05_SNMP_Info_Leak.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class SNMPInfoLeakPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def _build_snmp_get(self, community):
        # SNMPv1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)
        oid = b"\x30\x26\x02\x01\x00\x04"
        comm = community.encode()
        oid += bytes([len(comm)]) + comm
        oid += b"\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
        oid += b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
        return oid

    def exploit(self):
        port = 161
        self.logger.info(f"检测SNMP {self.target_ip}:{port}...")
        for community in ["public", "private", "community"]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                pkt = self._build_snmp_get(community)
                sock.sendto(pkt, (self.target_ip, port))
                data, _ = sock.recvfrom(4096)
                if len(data) > 10:
                    self.logger.warning(f"[+] SNMP community string '{community}' 有效！({len(data)} bytes)")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"SNMP community: {community}"
                    sock.close()
                    return self.results
                sock.close()
            except socket.timeout:
                continue
            except Exception:
                continue
        self.logger.info("SNMP未响应或默认community无效")
        self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 05_SNMP_Info_Leak.py <target_ip>")
        sys.exit(1)
    plugin = SNMPInfoLeakPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

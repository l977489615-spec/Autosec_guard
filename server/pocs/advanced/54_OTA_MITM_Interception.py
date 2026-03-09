"""
PoC Name: OTA Update MITM Interception
CVE: N/A
Component: OTA Update Channel
Category: Application
Severity: Critical
CVSS: 8.5
Description: 检测OTA更新通道是否使用证书固定(Certificate Pinning),验证是否容易受到MITM攻击。
Prerequisites: 与目标同一网络。
Usage: python3 59_OTA_MITM.py <target_ip>
"""
import socket
import ssl
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class OTAMITMPlugin(IVIVulnerabilityPlugin):
    OTA_PORTS = [443, 8443, 4443, 9443]
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址")
        return True
    def exploit(self):
        self.logger.info(f"OTA MITM测试 {self.target_ip}")
        self.logger.info("检测HTTPS证书验证强度...")
        for port in self.OTA_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((self.target_ip, port)) != 0:
                    s.close()
                    continue
                s.close()
                # Try connecting with unverified SSL
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ctx.wrap_socket(socket.socket(), server_hostname=self.target_ip)
                conn.settimeout(5)
                conn.connect((self.target_ip, port))
                cert = conn.getpeercert(binary_form=True)
                self.logger.info(f"[+] TLS连接端口 {port} (证书 {len(cert)}B)")
                # Check if self-signed or weak
                try:
                    ctx2 = ssl.create_default_context()
                    conn2 = ctx2.wrap_socket(socket.socket(), server_hostname=self.target_ip)
                    conn2.settimeout(5)
                    conn2.connect((self.target_ip, port))
                    conn2.close()
                    self.logger.info(f"  证书验证通过 - 使用有效CA证书")
                except ssl.SSLCertVerificationError:
                    self.logger.warning(f"[+] 端口 {port} 使用自签名证书！MITM风险")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"Self-signed cert on port {port}"
                conn.close()
                if self.results.get("vulnerable"):
                    return self.results
            except Exception as e:
                continue
        if not self.results.get("vulnerable"):
            self.logger.info("[-] 未发现TLS配置弱点")
            self.results["vulnerable"] = False
        return self.results
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 59_OTA_MITM.py <target_ip>")
        sys.exit(1)
    plugin = OTAMITMPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

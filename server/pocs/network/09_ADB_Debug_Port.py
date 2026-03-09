"""
PoC Name: ADB Debug Port Detection
CVE: CVE-2018-6242
Component: Android Debug Bridge (ADB) over TCP
Category: Network
Severity: Critical
CVSS: 9.8
Description: 检测IVI系统上ADB TCP端口(5555)是否开放,尝试ADB握手以确认未授权访问。
Prerequisites: 目标IVI运行Android系统且ADB over TCP已启用。
Usage: python3 27_ADB_Debug_Port.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class ADBDebugPortPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        return True

    def exploit(self):
        port = 5555
        self.logger.info(f"检测ADB端口 {self.target_ip}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            result = s.connect_ex((self.target_ip, port))
            if result != 0:
                self.logger.info(f"端口 {port} 关闭")
                self.results["vulnerable"] = False
                return self.results
            self.logger.info(f"端口 {port} 开放！尝试ADB握手...")
            # ADB CNXN packet
            s.send(b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1host::\x00")
            s.settimeout(3)
            resp = s.recv(1024)
            if b"CNXN" in resp:
                self.logger.warning("[+] ADB握手成功 - 存在未授权远程Shell访问！")
                self.results["vulnerable"] = True
                self.results["evidence"] = "ADB CNXN handshake accepted without auth"
            else:
                self.logger.info("ADB端口开放但握手失败,可能需要授权")
                self.results["vulnerable"] = False
            s.close()
        except Exception as e:
            self.logger.error(f"连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 27_ADB_Debug_Port.py <target_ip>")
        sys.exit(1)
    plugin = ADBDebugPortPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

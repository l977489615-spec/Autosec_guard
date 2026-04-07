"""
PoC Name: CAN Bus Traffic Capture
CVE: N/A
Component: CAN Bus (PCAN)
Category: Protocol
Severity: Medium
CVSS: 5.0
Description: 捕获CAN总线流量,分析帧ID分布和数据模式。
Prerequisites: PCAN接口(如PCAN_USBBUS1), python-can库, PCAN驱动。
Usage: python3 22_CAN_Bus_Sniff.py PCAN_USBBUS1
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

class CANBusSniffPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = "CAN Bus Sniff"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
    meta_protocol = "can"
    meta_target_os = ["all"]
    meta_required_params = ["can_interface"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        iface = self.params.get("can_interface", "PCAN_USBBUS1")
        self.logger.info(f"使用CAN接口: {iface}")
        return True

    def exploit(self):
        iface = self.params.get("can_interface", "PCAN_USBBUS1")
        self.logger.info(f"开始CAN总线流量捕获 ({iface}), 持续5秒...")
        try:
            import can
            if "PCAN" in iface:
                bus = can.interface.Bus(channel=iface, interface="pcan", bitrate=500000)
            else:
                bus = can.interface.Bus(channel=iface, bustype="socketcan")
            ids = {}
            start = time.time()
            count = 0
            while time.time() - start < 5:
                msg = bus.recv(timeout=0.5)
                if msg:
                    count += 1
                    aid = hex(msg.arbitration_id)
                    ids[aid] = ids.get(aid, 0) + 1
            bus.shutdown()
            self.logger.info(f"捕获 {count} 帧, {len(ids)} 个不同ID")
            for aid, cnt in sorted(ids.items(), key=lambda x: -x[1])[:10]:
                self.logger.info(f"  ID {aid}: {cnt} 帧")
            self.results["vulnerable"] = count > 0
            self.results["evidence"] = f"{count} frames, {len(ids)} unique IDs"
        except ImportError:
            self.logger.error("python-can未安装 (pip install python-can)")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"CAN捕获失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 22_CAN_Bus_Sniff.py <can_interface>")
        sys.exit(1)
    plugin = CANBusSniffPlugin({"target_ip": "N/A", "can_interface": sys.argv[1]})
    plugin.run_verify()

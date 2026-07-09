#!/usr/bin/env python3
"""
PoC Name: CAN Bus Traffic Capture
Identifier: CWE-200
Component: CAN Bus (PCAN)
Category: Protocol
Severity: Medium
CVSS: 5.0
Description: 捕获CAN总线流量,分析帧ID分布和数据模式。
Prerequisites: PCAN接口(如PCAN_USBBUS1), python-can库, PCAN驱动。
Usage: python3 01_CWE_200_CAN_Bus_Sniff_Active_Validation.py PCAN_USBBUS1
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

class CANBusSniffPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-CAN-001"
    meta_poc_name = 'CWE-200 CAN Bus 报文嗅探 Active Validation'
    meta_cve_id = "CWE-200"
    meta_source_url = "https://cwe.mitre.org/data/definitions/200.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/200.html']
    meta_severity = "Medium"
    meta_protocol = "can"
    meta_target_os = ["all"]
    meta_required_params = ["can_interface"]
    meta_profiles = ["recon", "can"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"使用CAN接口: {format_can_settings(settings)}")
        return True

    def exploit(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"开始CAN总线流量捕获 ({format_can_settings(settings)}), 持续5秒...")
        try:
            bus = open_can_bus(self.params)
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
        print("Usage: python3 01_CWE_200_CAN_Bus_Sniff_Active_Validation.py <can_interface>")
        sys.exit(1)
    plugin = CANBusSniffPlugin({"target_ip": "N/A", "can_interface": sys.argv[1]})
    plugin.run_verify()

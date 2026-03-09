"""
PoC Name: Bluetooth SDP Service Enumeration
CVE: N/A
Component: Bluetooth SDP
Category: Recon
Severity: Low
CVSS: 3.0
Description: 枚举目标蓝牙设备的SDP服务记录,发现可用的Profile和攻击面。
Prerequisites: Linux蓝牙适配器。
Usage: python3 49_BT_SDP_Enum.py <target_mac>
"""
import sys
import subprocess
from iv_plugin_base import IVIVulnerabilityPlugin
class BTSDPEnumPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        if not self.params.get("bd_addr"):
            raise RuntimeError("需要指定目标蓝牙MAC地址")
        return True
    def exploit(self):
        target = self.params["bd_addr"]
        self.logger.info(f"SDP服务枚举: {target}")
        try:
            result = subprocess.run(
                ["sdptool", "browse", target],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                services = result.stdout.count("Service Name:")
                self.logger.info(f"[+] 发现 {services} 个SDP服务")
                for line in result.stdout.splitlines():
                    if "Service Name:" in line or "Channel:" in line or "Protocol:" in line:
                        self.logger.info(f"  {line.strip()}")
                self.results["vulnerable"] = True
                self.results["evidence"] = f"{services} Bluetooth services found"
            else:
                self.logger.info("SDP查询失败或无服务")
                if result.stderr:
                    self.logger.info(f"  Error: {result.stderr[:200]}")
                self.results["vulnerable"] = False
        except FileNotFoundError:
            self.logger.error("sdptool未安装 (apt install bluez)")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"SDP枚举失败: {e}")
            self.results["vulnerable"] = False
        return self.results
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 49_BT_SDP_Enum.py <target_mac>")
        sys.exit(1)
    plugin = BTSDPEnumPlugin({"target_ip": "N/A", "bd_addr": sys.argv[1]})
    plugin.run_verify()

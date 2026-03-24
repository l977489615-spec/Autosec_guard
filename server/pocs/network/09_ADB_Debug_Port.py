"""
PoC Name: ADB Debug Port Detection
CVE: CVE-2018-6242
Component: Network Stack
Category: Network
Severity: Critical
CVSS: 9.8
Description: 扫描所有已知 ADB TCP 端口（5555/5556/5558/9527/6789/4444/7777/8888/9999/2233/4567/5037/1234）并尝试 ADB CNXN 握手，检测未授权远程 Shell 访问（含工程模式端口）
Prerequisites: 目标 IVI 运行 Android/HarmonyOS 系统，且 ADB over TCP 已启用。
Usage: python3 09_ADB_Debug_Port.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

# ADB CNXN 握手包（CONNECT 命令，Android ADB 协议 v1）
ADB_CNXN_PACKET = (
    b"CNXN"               # Command: CONNECT
    b"\x00\x00\x00\x01"  # Version: 0x01000000
    b"\x00\x10\x00\x00"  # Max data: 4096
    b"\x07\x00\x00\x00"  # Data length: 7
    b"\x32\x02\x00\x00"  # Data check
    b"\xbc\xb1\xa7\xb1"  # Magic
    b"host::\x00"         # System identity string
)

# 所有待检测的 ADB 端口（覆盖标准及已知非标准端口）
ADB_PORTS = [
    (5555, "标准 ADB over TCP"),
    (5556, "多设备顺延-2"),
    (5558, "多设备顺延-3"),
    (9527, "工程模式 (AION/国产 IVI)"),
    (6789, "HarmonyOS/鸿蒙车机"),
    (4444, "旧版 ADB server"),
    (7777, "MTK/高通车机测试"),
    (8888, "第三方工具监听"),
    (9999, "第三方工具监听"),
    (2233, "OEM 私有工程端口"),
    (4567, "OEM 私有工程端口"),
    (5037, "ADB server 本地通信"),
    (1234, "root 工具绑定"),
]


class ADBDebugPortPlugin(IVIVulnerabilityPlugin):
    """
    扫描目标所有已知 ADB TCP 端口，尝试 ADB CNXN 握手，
    确认是否存在未授权远程 Shell 访问。
    """

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标 IP 地址。")
        return True

    def _check_adb_port(self, port, port_desc, timeout=4):
        """
        尝试连接指定端口并发送 ADB CNXN 握手包。
        返回 (open: bool, adb_response: bool, banner: bytes)
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            ret = s.connect_ex((self.target_ip, port))
            if ret != 0:
                s.close()
                return False, False, b""
            # 端口开放，尝试 ADB 握手
            s.send(ADB_CNXN_PACKET)
            s.settimeout(2)
            try:
                resp = s.recv(1024)
            except socket.timeout:
                resp = b""
            s.close()
            adb_ok = b"CNXN" in resp
            return True, adb_ok, resp
        except Exception:
            return False, False, b""

    def exploit(self):
        host = self.target_ip
        
        # 1. 优先检测有线 / 本地相连的物理 ADB 设备 (USB)
        try:
            import subprocess
            adb_result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=5)
            if adb_result.returncode == 0:
                lines = adb_result.stdout.strip().split('\n')
                wired_devices = []
                for line in lines[1:]:  # Skip "List of devices attached"
                    line = line.strip()
                    if line and not line.startswith('*'):  # filter daemon logs
                        parts = line.split()
                        if len(parts) >= 2:
                            dev_id, status = parts[0], parts[1]
                            # 过滤掉模拟器和网络端点，只将其视为有线物理 USB 设备
                            if ":" not in dev_id and "emulator" not in dev_id:
                                wired_devices.append((dev_id, status))
                
                if wired_devices:
                    self.logger.warning(f"  [!!!] 发现真实物理直连的 USB ADB 设备: {wired_devices}")
                    self.results["vulnerable"] = True
                    details = "\n".join(f"  直连设备标示: {d[0]}, 授权状态: {d[1]}" for d in wired_devices)
                    self.results["evidence"] = f"【危】检测到车机向外部暴露了实体的有线 USB ADB 调试口:\n{details}"
                    print(f"[!] 【漏洞存在】物理接口暴露！车机引出了未关闭的有线 ADB 调试通道: {[d[0] for d in wired_devices]}")
                    # 若发现高危的物理底座泄露，直接报漏洞，可跳过后续网络扫描
                    return self.results
                else:
                    self.logger.info("  [-] 当前系统未检出直连的有线 ADB 设备。下放至网络端口扫描...")
        except FileNotFoundError:
            self.logger.debug("  [*] 扫描端未安装 `adb` 命令行工具，主动跳过有线 USB 接口检测。")
        except Exception as e:
            self.logger.debug(f"  [*] 尝试检测有线 ADB 状态时发生错误: {e}")

        # 2. 回退到基于 IP 的原生网络 TCP 扫描
        self.logger.info(
            f"开始网络扫描 {host} 上所有已知 ADB 端口（共 {len(ADB_PORTS)} 个）..."
        )

        open_ports = []       # 仅端口开放
        vulnerable_ports = [] # 端口开放且 ADB 握手成功

        for port, desc in ADB_PORTS:
            self.logger.info(f"  探测 {host}:{port} ({desc})...")
            is_open, is_adb, banner = self._check_adb_port(port, desc)

            if not is_open:
                self.logger.info(f"    [-] 端口关闭")
                continue

            self.logger.info(f"    [+] 端口开放！")
            open_ports.append((port, desc))

            if is_adb:
                self.logger.warning(
                    f"    [!!!] ADB 握手成功 (CNXN 响应) - 端口 {port} ({desc})"
                )
                vulnerable_ports.append((port, desc, banner[:40]))
            else:
                banner_preview = repr(banner[:32]) if banner else "(无响应)"
                self.logger.info(
                    f"    [*] ADB 握手未成功（可能非 ADB 服务或需授权）: {banner_preview}"
                )

        # 判断结果
        if vulnerable_ports:
            self.results["vulnerable"] = True
            details = "\n".join(
                f"  端口 {p} ({d}) - ADB CNXN 接受，banner: {repr(b)}"
                for p, d, b in vulnerable_ports
            )
            self.results["evidence"] = (
                f"发现 {len(vulnerable_ports)} 个未授权 ADB 端口（CVE-2018-6242）：\n"
                f"{details}"
            )
            print(
                f"[!] 【漏洞存在】CVE-2018-6242: 未授权 ADB 访问 - "
                f"漏洞端口: {[p for p,_,_ in vulnerable_ports]}"
            )
        elif open_ports:
            # 端口开放但握手未成功（可能是其他服务或 ADB 需要认证）
            self.results["vulnerable"] = False
            self.results["evidence"] = (
                f"发现 {len(open_ports)} 个开放端口但 ADB 握手均失败，可能已启用授权：\n"
                + "\n".join(f"  端口 {p} ({d})" for p, d in open_ports)
            )
        else:
            self.results["vulnerable"] = False
            self.results["evidence"] = (
                f"未发现任何已知 ADB 端口开放（共检测 {len(ADB_PORTS)} 个端口）"
            )
            self.logger.info("[-] 目标未开放任何已知 ADB 端口。")

        return self.results



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 09_ADB_Debug_Port.py <target_ip>")
        sys.exit(1)
    plugin = ADBDebugPortPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

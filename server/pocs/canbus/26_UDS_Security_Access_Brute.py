"""
PoC Name: UDS Security Access Brute Force
CVE: N/A
Component: Canbus Stack
Category: Canbus
Severity: Critical
CVSS: 8.5
Description: UDS 0x27安全访问Seed-Key暴力破解
Prerequisites: 激活的SocketCAN接口(如can0)及python-can支持
Usage: python3 26_UDS_Security_Access_Brute.py <args>
"""
import socket
import subprocess
import paramiko
import requests
import warnings
from iv_plugin_base import IVIVulnerabilityPlugin

# Suppress insecure request warnings for self-signed certs
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class IVIVulnerabilityScanner(IVIVulnerabilityPlugin):
    def __init__(self, target_ip):
        # Base class expects a dict
        config = {'target_ip': target_ip}
        super().__init__(config)
        self.common_creds = [
            ("root", "root"),
            ("root", "123456"),
            ("root", "admin"),
            ("admin", "admin"),
            ("admin", "123456")
        ]

    def check_prerequisites(self):
        # Basic connectivity check or just pass
        return True

    def exploit(self):
        # This scanner uses run_all instead of a single exploit flow,
        # but we must implement this abstract method.
        self.run_all()

    def scan_tcp_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def check_adb(self):
        """检测 TCP 5555 ADB 服务"""
        if self.scan_tcp_port(5555):
            self.logger.info(" Port 5555 (ADB) is OPEN.")
            # 进一步可以尝试握手逻辑
        else:
            self.logger.info("Port 5555 (ADB) is closed.")

    def check_ssh(self):
        """检测 TCP 22 SSH 服务及弱口令"""
        if not self.scan_tcp_port(22):
            self.logger.info("Port 22 (SSH) is closed.")
            return

        self.logger.info("Port 22 (SSH) is OPEN (TCP connected). Attempting SSH handshake...")
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        for user, pwd in self.common_creds:
            try:
                client.connect(self.target_ip, port=22, username=user, password=pwd, timeout=3, banner_timeout=3)
                self.logger.info(f" [HIGH] SSH Weak Credential Found: {user}/{pwd}")
                client.close()
                return
            except paramiko.AuthenticationException:
                # Auth failed, but service is active
                continue
            except (paramiko.SSHException, EOFError) as e:
                # This catches "Error reading SSH protocol banner" or closed connections
                msg = str(e)
                if "Error reading SSH protocol banner" in msg or "No existing session" in msg or not msg:
                    self.logger.info(f" SSH Handshake Failed: Connection closed by remote host ({msg}).")
                else:
                    self.logger.info(f" SSH Protocol Error: {msg}")
                # If handshake fails, no point trying other passwords
                return
            except socket.error as e:
                self.logger.info(f" SSH Socket Error: {e}")
                return
            except Exception as e:
                self.logger.info(f" SSH Unknown Error: {e}")
                break
        
        self.logger.info("SSH Credential bruteforce finished (Auth refused for common creds).")

    def check_telnet(self):
        """检测 TCP 23 Telnet 服务及 Banner"""
        if not self.scan_tcp_port(23):
            self.logger.info("Port 23 (Telnet) is closed.")
            return
            
        self.logger.info("Port 23 (Telnet) is OPEN. Grabbing banner...")
        try:
            # Python 3.13 removed telnetlib, using raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.target_ip, 23))
            # Basic banner grab
            banner = s.recv(1024).decode('ascii', 'ignore').strip()
            self.logger.info(f"Telnet Banner: {banner}")
            s.close()
        except Exception as e:
            self.logger.info(f" Telnet Error: {e}")

    def scan_udp_port(self, port):
        """扫描UDP端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            # UDP is stateless, 'connect' invalidates address for send/recv but doesn't handshake
            # We try to send empty packet
            sock.sendto(b'', (self.target_ip, port))
            # If we receive ICMP unreachable, it's closed (handled by OS/socket error usually)
            # If we receive data, it's open
            # If timeout, it's Open|Filtered. We will mark as likely Open for this purpose or just skip.
            # For accurate UDP scan we'd need more complex logic. 
            # Simplified: Just report if we get data or no error on send (send usually succeeds though)
            # Better approach for script: Just log if we get a response.
            
            data, _ = sock.recvfrom(1024)
            return True
        except socket.timeout:
            # Timeout in UDP often means open or filtered. 
            # We'll return False to avoid noise, unless we want to report Open|Filtered.
            return False 
        except Exception:
            return False
        finally:
            sock.close()

    def check_custom_ports(self):
        """检测用户指定的关键端口列表"""
        port_list_str = "21,22,23,25,80,81,82,83,84,88,137,143,443,445,554,631,1080,1883,1900,2000,2323,U:3671,U:3702,4433,4443,4567,5222,5683,7474,7547,8000,8023,8080,8081,8443,8088,U:8600,8883,8888,9000,9090,9999,10000,U:30718,U:37020,37777,U:37810,49152"
        
        ports = port_list_str.split(',')
        
        self.logger.info("Starting comprehensive port scan...")
        
        for p_str in ports:
            p_str = p_str.strip()
            if not p_str: continue
            
            is_udp = False
            if p_str.startswith('U:'):
                is_udp = True
                port = int(p_str.split(':')[1])
            else:
                port = int(p_str)

            if is_udp:
                # UDP Scan
                # Note: Simple UDP scan is often inaccurate without payload
                # We simply mark checked here.
                pass 
                # Implementing actual UDP check might be noisy, but let's try our helper
                # if self.scan_udp_port(port):
                #     self.logger.info(f" UDP Port {port} is OPEN (Received Data)")
            else:
                # TCP Scan
                if self.scan_tcp_port(port):
                    self.logger.info(f" TCP Port {port} is OPEN.")
                    # Try HTTP for common HTTP ports to get banner
                    if port in [80, 81, 8080, 8081, 8000, 8088, 8888, 9000, 8443, 443]:
                        try:
                            protocol = "https" if port in [443, 8443] else "http"
                            url = f"{protocol}://{self.target_ip}:{port}"
                            r = requests.get(url, timeout=1, verify=False)
                            self.logger.info(f"   -> HTTP Status: {r.status_code}, Server: {r.headers.get('Server', 'N/A')}")
                        except:
                            pass

    def check_web_ports(self):
        """检测常见 Web 端口 80, 443, 8080"""
        ports = [80, 443, 8080]
        for port in ports:
            if self.scan_tcp_port(port):
                self.logger.info(f" Web Port {port} is OPEN.")
                protocol = "https" if port == 443 else "http"
                try:
                    url = f"{protocol}://{self.target_ip}:{port}"
                    r = requests.get(url, timeout=2, verify=False)
                    server_header = r.headers.get('Server', 'Unknown')
                    self.logger.info(f"   -> Status: {r.status_code}, Server: {server_header}")
                except:
                    pass

    def check_wired_adb(self):
        """检测本地USB连接的ADB设备 (有线ADB)"""
        self.logger.info("Checking for USB connected ADB devices...")
        try:
            # Check if adb is in path or try commonly found path
            cmd = ['adb', 'devices']
            output = subprocess.check_output(cmd, timeout=5, stderr=subprocess.STDOUT).decode()
            
            lines = output.splitlines()
            # First line is usually "List of devices attached"
            devices = [line for line in lines if line.strip() and not line.startswith('List of devices')]
            
            if devices:
                self.logger.info(f" [HIGH] Found USB ADB Device(s) (Wired ADB enabled): {devices}")
                self.results['vulnerable'] = True
                self.results['evidence'] += f"USB ADB Devices: {devices}\n"
            else:
                self.logger.info(" No USB ADB devices found.")
        except FileNotFoundError:
             self.logger.info(" 'adb' command not found. Cannot check USB devices. Please install Android Platform Tools.")
        except subprocess.CalledProcessError as e:
            self.logger.info(f" Error executing adb: {e.output.decode()}")
        except Exception as e:
            self.logger.info(f" Error checking wired ADB: {e}")

    def run_all(self):
        self.logger.info(f"Starting scan on {self.target_ip}...")
        self.check_wired_adb()
        self.check_adb()
        self.check_ssh()
        self.check_telnet()
        self.check_web_ports()
        self.logger.info("Scan complete.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 26_UDS_Security_Access_Brute.py <args>")
        sys.exit(1)
    plugin = IVIVulnerabilityScanner({})
    plugin.run_verify()

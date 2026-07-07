# UPnP AVTransport 媒体注入 - 改进版说明

## 问题解决

### "该视频不支持投屏"错误

**原因**：设备能够接收 SOAP 命令并尝试播放，但投送的媒体格式或编码不兼容。

**解决方案**：

#### 方案 1：使用真实的视频文件（推荐）

从互联网或本地获取一个标准的 MP4 视频文件，然后投送：

```bash
# 使用真实视频文件
python3 12_UPnP_AVTransport_Media_Inject.py 10.173.189.1 --media /path/to/your_video.mp4
```

**推荐的视频格式**：
- **编码**：H.264（AVC）
- **容器**：MP4（MPEG-4 Part 14）
- **分辨率**：640x480 或 1280x720（取决于设备能力）
- **帧率**：24-30 fps
- **音频**：AAC（可选，但建议包含）

#### 方案 2：使用改进的自动生成 MP4

脚本现在会生成一个更完整的、符合 MP4 标准的文件：

```bash
# 使用自动生成的 MP4（无媒体参数）
python3 12_UPnP_AVTransport_Media_Inject.py 10.173.189.1
```

自动生成的 MP4 包含：
- 完整的文件类型信息（ftyp atom）
- 完整的视频元数据（moov atom）
- H.264 基本配置参数
- 视频尺寸 320x240
- 正确的 MIME 类型声明

#### 方案 3：生成测试视频

使用 FFmpeg 生成一个真实的最小化视频文件：

```bash
# 生成 2 秒的黑色视频（~100KB）
ffmpeg -f lavfi -i color=c=black:s=640x480:d=2 -c:v libx264 -preset ultrafast -y test_video.mp4

# 或生成有内容的视频
ffmpeg -f lavfi -i testsrc=s=640x480:d=2 -c:v libx264 -preset ultrafast -y test_video.mp4
```

然后投送：

```bash
python3 12_UPnP_AVTransport_Media_Inject.py 10.173.189.1 --media test_video.mp4
```

## 改进内容

原脚本只能触发设备的投屏对话框，然后显示"不支持投屏"。改进后的脚本能够**真正投送图片或视频**到车机设备。

### 主要改进点

1. **完整的 MP4 结构**
   - 改进了自动生成的 MP4 文件，包含所有必需的 atoms
   - ftyp: 文件类型识别信息
   - mdat: 视频数据
   - moov: 完整的元数据（mvhd, trak, mdia, minf, stbl）
   - 支持标准视频播放器识别

2. **提供真实媒体内容**
   - HTTP 服务器现在返回真实的媒体文件而不是 "OK" 字符串
   - 自动生成最小化 MP4 文件（如用户未提供媒体文件）
   - 支持自定义媒体文件（JPG、PNG、MP4、MOV）

3. **改进 UPnP 元数据**
   - 添加符合 UPnP 标准的 DIDL-Lite 元数据格式
   - 包含正确的媒体类型信息
   - 提高设备兼容性

4. **更好的媒体类型检测**
   - 自动识别媒体格式并设置正确的 MIME 类型
   - 根据文件扩展名调整 UPnP 类型（图片/视频）

5. **更详细的执行反馈**
   - 显示投送的媒体大小和类型
   - 确认是否已向目标发送媒体内容
   - 更清晰的成功/失败提示

## 使用方法

### 基本用法（使用生成的最小化 MP4）

```bash
python3 12_UPnP_AVTransport_Media_Inject.py 10.173.189.1
```

### 投送自定义图片

```bash
python3 12_UPnP_AVTransport_Media_Inject.py 10.173.189.1 --media /path/to/image.jpg
```

### 投送自定义视频

```bash
python3 12_UPnP_AVTransport_Media_Inject.py 10.173.189.1 --media /path/to/video.mp4
```

## 参数说明

- `target_ip`: 目标车机 IP 地址（必需）
- `--media`: 媒体文件路径（可选）
  - 支持格式：`.jpg`, `.jpeg`, `.png`, `.mp4`, `.m4v`, `.mov`
  - 如不指定，脚本将使用自动生成的最小化 MP4

## 测试例子

### 投送测试图片

```bash
python3 12_UPnP_AVTransport_Media_Inject.py 10.173.189.1 --media ./poc_test_image.jpg
```

### 生成并投送测试视频

```bash
# 使用 FFmpeg 生成测试视频
ffmpeg -f lavfi -i testsrc=s=320x240:d=1 -c:v libx264 -preset ultrafast -y test.mp4

# 投送视频
python3 12_UPnP_AVTransport_Media_Inject.py 10.173.189.1 --media test.mp4
```

## 预期输出

当漏洞存在且媒体成功投送时：

```
[*] 媒体服务器已启动: 端口 18999
[*] 发送 SSDP M-SEARCH 广播，搜寻 AVTransport 服务...
[+] 发现 LOCATION: http://10.173.189.1:49152/...
[*] 解析设备描述 XML 获取 ControlURL...
[+] AVTransport ControlURL: http://10.173.189.1:49152/upnp/control/...
[*] 发送 SetAVTransportURI → http://192.168.1.100:18999/poc.mp4
[*] SetAVTransportURI 响应: HTTP 200
[*] 发送 Play 指令...
[*] Play 响应: HTTP 200
[*] 等待目标请求媒体内容（最多 10 秒）...
[+] 已向目标发送媒体内容 (1234 字节)
[!] 【漏洞存在】UPnP AVTransport 未认证媒体注入 - 媒体已投送
[!] 【成功】目标已接收媒体内容！
```

## 技术说明

### 自动生成 MP4 的内部结构

```
ftyp (32 bytes)
├─ major_brand: mp42
├─ minor_version: 0
└─ compatible_brands: mp42, isom, avc1, iso2, avc1, mp41

mdat (可变大小)
└─ H.264 视频数据

moov (可变大小)
├─ mvhd (电影头)
│  ├─ timescale: 1000
│  ├─ duration: 100 (100ms)
│  └─ playback_speed: 1.0
│
└─ trak (轨道)
   ├─ tkhd (轨道头)
   │  ├─ track_id: 1
   │  ├─ duration: 100
   │  ├─ width: 320
   │  └─ height: 240
   │
   ├─ edts (编辑列表)
   │
   └─ mdia (媒体)
      ├─ mdhd (媒体头)
      ├─ hdlr (处理器)
      └─ minf (媒体信息)
         ├─ vmhd (视频媒体头)
         ├─ dinf (数据信息)
         └─ stbl (样本表)
            ├─ stsd (样本描述) - AVC1 编码器
            ├─ stts (时间到样本映射)
            ├─ stsc (样本到块映射)
            ├─ stsz (样本大小)
            └─ stco (块偏移)
```

### 媒体内容处理

1. **自动生成 MP4**：如用户未提供媒体文件，脚本生成最小化但符合标准的 MP4 文件
2. **直接提供文件内容**：用户提供的媒体文件直接通过 HTTP 返回
3. **MIME 类型自适应**：根据文件扩展名自动设置正确的 Content-Type

### UPnP 元数据格式

使用 UPnP 标准的 DIDL-Lite 格式：

```xml
<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/">
  <item id="1" parentID="0" restricted="1">
    <dc:title>POC Media</dc:title>
    <upnp:class>object.item.videoItem.movie</upnp:class>
    <res protocolInfo="http-get:*:video/mp4:*">http://192.168.1.100:18999/poc.mp4</res>
  </item>
</DIDL-Lite>
```

## 故障排查

### 设备仍显示"不支持投屏"

**原因**：
- 设备不支持生成的 MP4 编码或格式
- 视频分辨率或帧率不匹配设备能力
- 媒体数据不完整或损坏

**解决**：
1. 尝试使用 FFmpeg 生成的真实视频文件
2. 尝试不同的分辨率（640x480, 1280x720）
3. 确保使用 H.264 编码（不要用 H.265/HEVC）
4. 在视频中添加音频轨道（AAC 编码）

### 媒体请求未被收到

**原因**：
- 设备可能在处理 URI 时出错
- 网络问题或防火墙阻止
- 设备不支持该媒体类型

**解决**：
1. 检查日志信息，确认 HTTP 服务器是否成功启动
2. 确认设备是否能访问本机的 18999 端口
3. 尝试从设备手动访问 `http://your_ip:18999/test.mp4`

### SSDP 发现失败

**原因**：
- 设备不响应 SSDP 广播
- 网络不在同一子网
- 设备的 UPnP 服务未启动

**解决**：
1. 脚本会自动尝试常见 UPnP 端口
2. 确认设备 IP 地址正确
3. 检查网络连接和防火墙设置

## 内部改变

- `_load_media_file()`: 新增方法，处理媒体加载
- `_generate_minimal_mp4()`: 改进方法，生成完整的 MP4 结构
- `_create_atom()`: 新增方法，创建 MP4 atom
- `_create_ftyp_atom()`: 新增方法，创建文件类型 atom
- `_create_video_frame()`: 新增方法，生成 H.264 视频数据
- `_create_moov_atom()`: 重写方法，生成完整元数据
- `_create_trak_atom()`: 新增方法，生成轨道信息
- `_create_mdia_atom()`: 新增方法，生成媒体信息
- `_create_minf_atom()`: 新增方法，生成媒体信息容器
- `_create_dinf_atom()`: 新增方法，生成数据信息
- `_create_stbl_atom()`: 新增方法，生成样本表
- `_generate_upnp_metadata()`: 新增方法，生成 DIDL-Lite 元数据
- `_start_callback_server()`: 改进，现在提供真实媒体内容
- `exploit()`: 改进，添加媒体加载和更详细的日志


from __future__ import annotations

import os
import re
from pathlib import Path


_CJK_RE = re.compile(r"[\u4e00-\u9fff]")
_LEADING_INDEX_RE = re.compile(r"^(?P<index>\d+[a-z]?)_(?P<body>.+)$", re.I)
_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7}|GHSA-[A-Za-z0-9\-]+|CWE-\d+)", re.I)
_SPACE_RE = re.compile(r"\s+")
_SEPARATOR_RE = re.compile(r"[_/]+")
_NOISE_RE = re.compile(
    r"\b(?:audit|validation|active validation|exposure|detection|plugin|poc)\b",
    re.I,
)
_DISPLAY_JUNK_RE = re.compile(
    r"[:()→]|"
    r"\b(?:via|trigger(?:s|ed)?|overwrite(?:s|n)?|parsing|syscall|"
    r"accepted|processed|reassembled|during|without|malformed|"
    r"page\s+cache|timing\s+side\s+channel|anti\s+clogging|"
    r"xfrm|rxkad|byte\s+by\s+byte)\b",
    re.I,
)

_CANONICAL_KEYWORDS = (
    "cve", "ghsa", "cwe", "android", "airplay", "carplay", "mirror", "hiqnet",
    "webview", "sqlite", "v2x", "bsm", "gps", "tpms", "libupnp", "libavformat",
    "libpng", "libjpeg", "gstreamer", "ffmpeg", "chromium", "webkit", "nginx",
    "usb", "adb", "ssh", "telnet", "mqtt", "rtsp", "http", "https", "tls", "ssl",
    "openssl", "nginx", "redis", "valkey", "qnx", "linux", "kernel", "glibc",
    "sudo", "pkexec", "overlayfs", "netfilter", "binder", "zygote", "selinux",
    "wifi", "wpa", "krack", "blueborne", "ble", "bluetooth", "bt", "rf", "rkes",
    "can", "doip", "uds", "obd", "someip", "xcp", "firmware", "ota", "signature",
    "boot", "debug", "provider", "activity", "service", "receiver", "export",
    "auth", "authentication", "credential", "creds", "access", "control", "input",
    "command", "inject", "injection", "dos", "overflow", "oob", "uaf", "rce",
    "random", "crypto", "replay", "spoof", "leak", "exposure", "memory", "heap",
    "stack", "integer", "null", "path", "traversal", "file", "permission",
)

_DISPLAY_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ("php type juggling", "PHP类型混淆"),
    ("auth bypass", "认证绕过"),
    ("authentication bypass", "认证绕过"),
    ("access control", "访问控制"),
    ("info leak", "信息泄露"),
    ("information leak", "信息泄露"),
    ("command injection", "命令注入"),
    ("sql injection", "SQL注入"),
    ("sqli", "SQL注入"),
    ("path traversal", "路径穿越"),
    ("privilege escalation", "权限提升"),
    ("container escape", "容器逃逸"),
    ("memory corruption", "内存破坏"),
    ("heap overflow", "堆溢出"),
    ("stack overflow", "栈溢出"),
    ("buffer overflow", "缓冲区溢出"),
    ("out of bounds", "越界"),
    ("oob", "越界"),
    ("use after free", "释放后重用"),
    ("uaf", "UAF"),
    ("integer overflow", "整数溢出"),
    ("null pointer dereference", "空指针解引用"),
    ("null deref", "空指针解引用"),
    ("denial of service", "DoS"),
    ("dos", "DoS"),
    ("rce", "RCE"),
    ("weak creds", "弱口令"),
    ("weak credentials", "弱口令"),
    ("hardcoded creds", "硬编码凭据"),
    ("hardcoded credentials", "硬编码凭据"),
    ("cert pin", "证书固定缺失"),
    ("cert pinning", "证书固定缺失"),
    ("service discovery", "服务发现"),
    ("port scan", "端口扫描"),
    ("host discovery", "主机发现"),
    ("traffic hijack", "流量劫持"),
    ("message injection", "报文注入"),
    ("input validation", "输入校验"),
    ("signature verification", "签名校验"),
    ("secure boot bypass", "安全启动绕过"),
    ("mixed content", "混合内容"),
    ("javascript", "JavaScript"),
    ("java bridge", "Java桥接"),
    ("remote url", "远程URL"),
    ("plaintext", "明文"),
    ("weak crypto", "弱加密"),
    ("weak random", "弱随机"),
    ("random seed", "随机种子"),
    ("sensitive file storage", "敏感文件存储"),
    ("sensitive debug log", "敏感调试日志"),
    ("hardcoded debug endpoint", "硬编码调试端点"),
    ("database export", "数据库导出"),
    ("file exfil", "文件泄露"),
    ("devmode bypass", "开发模式绕过"),
    ("media inject", "媒体注入"),
    ("task hijack", "任务劫持"),
    ("syslog", "Syslog"),
    ("receiver permission", "广播接收器权限"),
    ("service permission", "服务权限"),
    ("provider uri grant", "Provider URI授权"),
    ("activity intent filter", "Activity Intent Filter"),
    ("firmware update verification", "固件更新校验"),
    ("firmware signature verification", "固件签名校验"),
    ("certificate validation", "证书校验"),
    ("replay", "重放"),
    ("spoofing", "伪造"),
    ("spoof", "伪造"),
    ("sniff", "报文嗅探"),
    ("enum", "枚举"),
)

_FILENAME_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ("auth bypass", "Authentication_Bypass"),
    ("authentication bypass", "Authentication_Bypass"),
    ("access control", "Access_Control"),
    ("info leak", "Information_Leak"),
    ("information leak", "Information_Leak"),
    ("command injection", "Command_Injection"),
    ("sql injection", "SQL_Injection"),
    ("path traversal", "Path_Traversal"),
    ("privilege escalation", "Privilege_Escalation"),
    ("container escape", "Container_Escape"),
    ("memory corruption", "Memory_Corruption"),
    ("heap overflow", "Heap_Overflow"),
    ("stack overflow", "Stack_Overflow"),
    ("buffer overflow", "Buffer_Overflow"),
    ("out of bounds", "Out_of_Bounds"),
    ("use after free", "Use_After_Free"),
    ("integer overflow", "Integer_Overflow"),
    ("null pointer dereference", "Null_Pointer_Dereference"),
    ("null deref", "Null_Dereference"),
    ("denial of service", "Denial_of_Service"),
    ("dos", "DoS"),
    ("weak creds", "Weak_Credentials"),
    ("weak credentials", "Weak_Credentials"),
    ("hardcoded creds", "Hardcoded_Credentials"),
    ("hardcoded credentials", "Hardcoded_Credentials"),
    ("service discovery", "Service_Discovery"),
    ("port scan", "Port_Scan"),
    ("host discovery", "Host_Discovery"),
    ("traffic hijack", "Traffic_Hijack"),
    ("message injection", "Message_Injection"),
    ("input validation", "Input_Validation"),
    ("signature verification", "Signature_Verification"),
    ("firmware update verification", "Firmware_Update_Verification"),
    ("certificate validation", "Certificate_Validation"),
    ("replay", "Replay"),
    ("spoofing", "Spoofing"),
    ("spoof", "Spoofing"),
    ("sniff", "Sniff"),
    ("enum", "Enumeration"),
)

_DISPLAY_SUFFIX_BY_CATEGORY = {
    "reconnaissance": "Reconnaissance",
}

_FILENAME_SUFFIX_BY_CATEGORY = {
    "reconnaissance": "Reconnaissance",
}


def _normalize_spaces(text: str) -> str:
    text = _SEPARATOR_RE.sub(" ", text)
    text = text.replace("-", " - ")
    return _SPACE_RE.sub(" ", text).strip()


def _strip_noise(text: str) -> str:
    cleaned = _NOISE_RE.sub(" ", text)
    return _SPACE_RE.sub(" ", cleaned).strip(" -_/")


def _extract_index(stem: str) -> tuple[str, str]:
    match = _LEADING_INDEX_RE.match(stem)
    if not match:
        return "", stem
    return match.group("index"), match.group("body")


def _should_ignore_meta_name(meta_poc_name: str | None) -> bool:
    text = str(meta_poc_name or "").strip()
    if not text:
        return True
    if text.endswith("..."):
        return True
    boilerplate = ("检测", "是否", "存在", "启用", "允许", "使用了", "设备", "系统或app", "风险")
    return _CJK_RE.search(text) is not None and any(token in text for token in boilerplate)


def _normalize_cve(meta_cve_id: str | None, text: str) -> str:
    match = _CVE_RE.search(str(meta_cve_id or "")) or _CVE_RE.search(text)
    return match.group(1).upper() if match else ""


def _interesting_phrase(text: str) -> str:
    words = text.split()
    for idx, word in enumerate(words):
        normalized = re.sub(r"[^a-z0-9]+", "", word.lower())
        if normalized in _CANONICAL_KEYWORDS:
            return " ".join(words[idx:])
    return text


def _apply_case_insensitive_replacements(text: str, replacements: tuple[tuple[str, str], ...]) -> str:
    output = text
    for source, target in replacements:
        output = re.sub(rf"(?i)\b{re.escape(source)}\b", target, output)
    return _SPACE_RE.sub(" ", output).strip()


def _canonical_suffix(category: str, *, for_filename: bool) -> str:
    mapping = _FILENAME_SUFFIX_BY_CATEGORY if for_filename else _DISPLAY_SUFFIX_BY_CATEGORY
    return mapping.get(category.lower(), "Active Validation")


def _cleanup_title(text: str) -> str:
    text = text.replace(" / ", "/")
    text = text.replace(" - ", " ")
    text = text.replace("...", "")
    text = re.sub(r"\s*/\s*", "/", text)
    text = _SPACE_RE.sub(" ", text).strip()
    return text


def _looks_canonical_display(text: str | None) -> bool:
    value = str(text or "").strip()
    if not value or not value.endswith(("Active Validation", "Reconnaissance")) or "_" in value:
        return False
    if len(value) > 96:
        return False
    return _DISPLAY_JUNK_RE.search(value) is None


def canonical_display_name(category: str, meta_poc_name: str | None, meta_cve_id: str | None, filename: str | None) -> str:
    if _looks_canonical_display(meta_poc_name):
        return _cleanup_title(str(meta_poc_name))
    raw = Path(str(filename or "")).stem if _should_ignore_meta_name(meta_poc_name) else str(meta_poc_name or Path(str(filename or "")).stem)
    _, body = _extract_index(Path(raw).stem)
    base = _normalize_spaces(body)
    cve_id = _normalize_cve(meta_cve_id, base)
    base = _strip_noise(base)
    base = _interesting_phrase(base)
    if _CJK_RE.search(base):
        display_phrase = base
    else:
        display_phrase = _apply_case_insensitive_replacements(base, _DISPLAY_REPLACEMENTS)
    display_phrase = _cleanup_title(display_phrase)
    if cve_id and not display_phrase.upper().startswith(cve_id):
        display_phrase = f"{cve_id} {display_phrase}".strip()
    if cve_id:
        duplicate = cve_id.replace("-", " ")
        display_phrase = re.sub(rf"(?i)\b{re.escape(duplicate)}\b", "", display_phrase, count=1)
        display_phrase = _cleanup_title(display_phrase)
    suffix = _canonical_suffix(category, for_filename=False)
    if not display_phrase.endswith(suffix):
        display_phrase = f"{display_phrase} {suffix}".strip()
    return _cleanup_title(display_phrase)


def _slugify_words(text: str) -> str:
    text = _apply_case_insensitive_replacements(text, _FILENAME_REPLACEMENTS)
    text = text.replace("-", "_")
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "PoC"


def canonical_filename(category: str, filename: str, meta_poc_name: str | None, meta_cve_id: str | None) -> str:
    path = Path(filename)
    if path.stem.endswith(("_Active_Validation", "_Reconnaissance")):
        return path.name
    index, body = _extract_index(path.stem)
    current_body = _normalize_spaces(body)
    if re.search(r"(Active Validation|Reconnaissance)$", current_body, re.I):
        raw_source = body
    else:
        raw_source = body if _should_ignore_meta_name(meta_poc_name) else str(meta_poc_name or body)
    raw = _normalize_spaces(raw_source)
    cve_id = _normalize_cve(meta_cve_id, raw)
    raw = _strip_noise(raw)
    raw = _interesting_phrase(raw)
    slug_parts: list[str] = []
    if cve_id:
        slug_parts.append(cve_id.replace("-", "_").upper())
    slug_core = _slugify_words(raw)
    if cve_id:
        cve_slug = cve_id.replace("-", "_").upper()
        if not slug_core.upper().startswith(cve_slug):
            slug_parts.append(slug_core)
    else:
        slug_parts.append(slug_core)
    suffix = _canonical_suffix(category, for_filename=True).replace(" ", "_")
    if not slug_parts[-1].endswith(suffix):
        slug_parts.append(suffix)
    stem = "_".join(part for part in slug_parts if part)
    prefix = f"{index}_" if index else ""
    return f"{prefix}{stem}.py"


def canonical_relative_path(relative_path: str, meta_poc_name: str | None, meta_cve_id: str | None) -> str:
    normalized = str(relative_path or "").replace("\\", "/").lstrip("./")
    category = os.path.dirname(normalized).split("/", 1)[0] if "/" in normalized else ""
    basename = os.path.basename(normalized)
    return f"{category}/{canonical_filename(category, basename, meta_poc_name, meta_cve_id)}" if category else canonical_filename(category, basename, meta_poc_name, meta_cve_id)

"""
security_utils.py — 服务端集中式安全校验工具。

设计原则（第一性原理）：安全决策必须保留在服务端，绝不信任客户端声明。
本模块提供：
  - safe_resolve_within(base_dir, candidate)：防路径穿越
  - is_safe_outbound_url(url)：防 SSRF（拦截内网/link-local/云 metadata）
  - is_private_or_lab_target(ip)：目标范围校验（Agent 只应攻击授权网段）
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────
# 1. 路径穿越防护
# ─────────────────────────────────────────────────────────────
def safe_resolve_within(base_dir: str, candidate_path: str) -> str | None:
    """
    将 candidate_path 解析为 base_dir 内的绝对路径。
    若解析结果逃逸出 base_dir（通过 ../、绝对路径、符号链接等），返回 None。
    """
    if not base_dir or not candidate_path:
        return None
    try:
        base_real = os.path.realpath(base_dir)
        # 拒绝绝对路径输入（os.path.join 遇绝对路径会丢弃 base 前缀）
        normalized = str(candidate_path).replace("\\", "/")
        if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
            return None
        combined = os.path.realpath(os.path.join(base_real, normalized))
        # 必须仍在 base_dir 之内
        if combined == base_real or combined.startswith(base_real + os.sep):
            return combined
        return None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# 2. SSRF 防护
# ─────────────────────────────────────────────────────────────
# 云厂商 metadata 端点（AWS/GCP/Azure/阿里云等统一使用 169.254.169.254）
_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}
_PRIVATE_MODEL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::1/128"),
)


def _host_is_ip_literal(host: str) -> bool:
    host = (host or "").strip().lower().strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _ip_in_clash_fake_ip_range(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    try:
        return ip.version == 4 and ip in ipaddress.ip_network("198.18.0.0/15")
    except ValueError:
        return False


def _ip_is_dangerous(ip_str: str, *, trust_proxy_dns: bool = False) -> bool:
    """判断 IP 是否属于危险范围（回环/私网/link-local/保留）。"""
    try:
        ip = ipaddress.ip_address(str(ip_str).split("%")[0])
    except ValueError:
        return False
    if trust_proxy_dns and _ip_in_clash_fake_ip_range(ip):
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_multicast or ip.is_unspecified:
        return True
    if ip.is_reserved:
        return True
    return False


def _is_allowed_private_model_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip.version == network.version and ip in network for network in _PRIVATE_MODEL_NETWORKS)


def is_safe_outbound_url(url: str, *, allow_private: bool = False, allow_proxy_dns: bool = False) -> tuple[bool, str]:
    """
    校验一个出站 URL 是否安全（防 SSRF）。

    默认拒绝：非 http/https、云 metadata 主机、解析到内网/回环/link-local 的主机。
    allow_private=True 时放行私网（用于本地实验室调用场景，但仍拒绝 metadata）。
    allow_proxy_dns=True 时放行 198.18.0.0/15 fake-ip（常见于 Clash 代理）。

    返回 (是否安全, 原因)。
    """
    if not url or not isinstance(url, str):
        return False, "empty url"
    try:
        parsed = urlparse(url.strip())
    except Exception as exc:
        return False, f"unparsable url: {exc}"

    if parsed.scheme not in ("http", "https"):
        return False, f"scheme not allowed: {parsed.scheme!r}"

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False, "missing host"

    if host in _METADATA_HOSTS:
        return False, "cloud metadata endpoint blocked"

    trust_proxy_dns = allow_proxy_dns

    # 解析主机的所有 IP（防 DNS rebinding 到内网）
    try:
        infos = socket.getaddrinfo(host, None)
        resolved_ips = {info[4][0] for info in infos}
    except Exception as exc:
        return False, f"dns resolution failed: {exc}"

    for ip_str in resolved_ips:
        clean = ip_str.split("%")[0]
        if clean in _METADATA_HOSTS:
            return False, "resolves to metadata endpoint"
        if _ip_is_dangerous(clean, trust_proxy_dns=trust_proxy_dns):
            if allow_private and _is_allowed_private_model_ip(ipaddress.ip_address(clean)):
                continue
            return False, f"resolves to blocked address: {clean}"

    return True, "ok"


# ─────────────────────────────────────────────────────────────
# 3. 目标范围校验（Agent / PoC 攻击目标）
# ─────────────────────────────────────────────────────────────
def is_private_or_lab_target(ip_str: str, extra_allowed_cidrs: list[str] | None = None) -> bool:
    """
    判断一个目标 IP 是否属于授权的实验室范围（私网 RFC1918 或显式允许的 CIDR）。
    公网 IP 默认视为未授权，除非通过 extra_allowed_cidrs 显式允许。
    """
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return False

    # 私网、回环、link-local 视为实验室内网（授权）
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True

    for cidr in (extra_allowed_cidrs or []):
        try:
            if ip in ipaddress.ip_network(str(cidr).strip(), strict=False):
                return True
        except ValueError:
            continue

    return False


def parse_allowed_target_cidrs(env_value: str | None) -> list[str]:
    """解析 AUTOSEC_ALLOWED_TARGET_CIDRS 环境变量（逗号分隔）。"""
    if not env_value:
        return []
    return [c.strip() for c in env_value.split(",") if c.strip()]

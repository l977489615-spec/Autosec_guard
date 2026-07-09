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


def _ip_is_dangerous(ip_str: str) -> bool:
    """判断 IP 是否属于危险范围（回环/私网/link-local/保留）。"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_loopback
        or ip.is_link_local      # 169.254.x.x（含云 metadata）
        or ip.is_private         # 10/8, 172.16/12, 192.168/16
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_safe_outbound_url(url: str, *, allow_private: bool = False) -> tuple[bool, str]:
    """
    校验一个出站 URL 是否安全（防 SSRF）。

    默认拒绝：非 http/https、云 metadata 主机、解析到内网/回环/link-local 的主机。
    allow_private=True 时放行私网（用于本地实验室调用场景，但仍拒绝 metadata）。

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

    # 解析主机的所有 IP（防 DNS rebinding 到内网）
    try:
        infos = socket.getaddrinfo(host, None)
        resolved_ips = {info[4][0] for info in infos}
    except Exception as exc:
        return False, f"dns resolution failed: {exc}"

    for ip_str in resolved_ips:
        # 去掉 IPv6 scope
        clean = ip_str.split("%")[0]
        if clean in _METADATA_HOSTS:
            return False, "resolves to metadata endpoint"
        if _ip_is_dangerous(clean):
            if allow_private and ipaddress.ip_address(clean).is_private:
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

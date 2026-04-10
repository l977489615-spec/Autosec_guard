import os
import re
import socket
import subprocess
from pathlib import Path
from urllib.parse import quote, urlparse


def _looks_local(base: str) -> bool:
    normalized = (base or "").strip().lower()
    return (
        not normalized
        or "localhost" in normalized
        or "127.0.0.1" in normalized
        or "0.0.0.0" in normalized
    )


def _is_private_ipv4(ip: str) -> bool:
    parts = [int(part) for part in ip.split(".") if part.isdigit()]
    if len(parts) != 4:
        return False
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    return False


def _should_skip_interface(name: str) -> bool:
    normalized = (name or "").strip().lower()
    blocked_prefixes = (
        "lo",
        "utun",
        "tun",
        "tap",
        "gif",
        "stf",
        "bridge",
        "br-",
        "docker",
        "veth",
        "vmenet",
        "vmnet",
        "awdl",
        "llw",
        "ap",
        "anpi",
    )
    return normalized.startswith(blocked_prefixes)


def _interface_priority(name: str, status: str) -> tuple[int, int]:
    normalized = (name or "").strip().lower()
    physical_prefixes = ("en", "eth", "wlan", "wifi", "wl", "wlp", "wlx")
    is_physical = 0 if normalized.startswith(physical_prefixes) else 1
    is_active = 0 if (status or "").strip().lower() == "active" else 1
    return (is_active, is_physical)


def _detect_primary_ipv4_from_ifconfig() -> str:
    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
    except Exception:
        return ""
    if result.returncode != 0 or not result.stdout.strip():
        return ""

    interfaces = []
    current = None
    for raw_line in result.stdout.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if not raw_line.startswith("\t") and not raw_line.startswith(" "):
            match = re.match(r"^([A-Za-z0-9._:-]+):", line)
            if not match:
                current = None
                continue
            current = {"name": match.group(1), "status": "", "ips": []}
            interfaces.append(current)
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("status:"):
            current["status"] = stripped.split(":", 1)[1].strip()
            continue
        inet_match = re.match(r"inet (\d+\.\d+\.\d+\.\d+)\b", stripped)
        if inet_match:
            ip = inet_match.group(1)
            if not ip.startswith("127.") and ip != "0.0.0.0":
                current["ips"].append(ip)

    candidates = []
    for item in interfaces:
        if _should_skip_interface(item["name"]):
            continue
        for ip in item["ips"]:
            if _is_private_ipv4(ip):
                candidates.append((item["name"], item["status"], ip))

    if not candidates:
        for item in interfaces:
            if _should_skip_interface(item["name"]):
                continue
            for ip in item["ips"]:
                candidates.append((item["name"], item["status"], ip))

    if not candidates:
        return ""

    candidates.sort(key=lambda item: _interface_priority(item[0], item[1]))
    return candidates[0][2]


def _detect_primary_ipv4() -> str:
    override = (os.environ.get("AUTOSEC_PUBLIC_HOST") or "").strip()
    if override:
        return override

    detected_from_ifconfig = _detect_primary_ipv4_from_ifconfig()
    if detected_from_ifconfig:
        return detected_from_ifconfig

    try:
        hostname_ip = socket.gethostbyname(socket.gethostname())
        normalized = str(hostname_ip).strip()
        if normalized and not normalized.startswith("127.") and normalized != "0.0.0.0":
            return normalized
    except Exception:
        pass
    return ""


def _extract_port(parsed) -> str:
    if parsed.port:
        return str(parsed.port)
    if parsed.scheme == "https":
        return "443"
    return "80"


def _rebuild_with_host(parsed, host: str, fallback_port: str) -> str:
    if not host:
        return ""
    scheme = (parsed.scheme if parsed and parsed.scheme else "http").strip()
    port = fallback_port or _extract_port(parsed)
    host_with_port = host
    if (scheme == "http" and port != "80") or (scheme == "https" and port != "443"):
        host_with_port = f"{host}:{port}"
    return f"{scheme}://{host_with_port}"


def resolve_public_edge_api_base(
    configured_base: str,
    request_host_url: str,
    *,
    forwarded_host: str = "",
    forwarded_proto: str = "",
) -> str:
    request_base = (request_host_url or "").strip().rstrip("/")
    configured = (configured_base or "").strip()
    configured_parsed = urlparse(configured) if configured else None
    request_parsed = urlparse(request_base) if request_base else None
    request_port = _extract_port(request_parsed) if request_parsed and request_parsed.netloc else _extract_port(configured_parsed)

    if forwarded_host:
        proto = (forwarded_proto or (request_parsed.scheme if request_parsed else "") or "http").strip()
        return f"{proto}://{forwarded_host.strip().rstrip('/')}"

    detected_ip = _detect_primary_ipv4()
    if detected_ip:
        base_parsed = request_parsed or configured_parsed
        rebuilt = _rebuild_with_host(base_parsed, detected_ip, request_port)
        if rebuilt:
            return rebuilt

    # Prefer the actual host used by the current request so generated install commands
    # follow the live server address instead of a stale AUTOSEC_API setting.
    if not _looks_local(request_base):
        return request_base

    if not _looks_local(configured):
        return configured.rstrip("/")

    return request_base


def edge_runtime_artifact_path(configured_path: str, edge_build_dir: Path, edge_dist_dir: Path) -> Path:
    configured = (configured_path or "").strip()
    if configured:
        return Path(configured).expanduser()
    preferred = edge_build_dir / "autosec-edge"
    if preferred.exists():
        return preferred
    return edge_dist_dir / "autosec-edge"


def edge_runtime_download_path(
    configured_path: str,
    requested_os: str,
    requested_arch: str,
    edge_build_dir: Path,
    edge_dist_dir: Path,
) -> Path:
    filename = f"autosec-edge-{requested_os}-{requested_arch}"
    if requested_os == "windows":
        filename += ".exe"

    search_roots = []
    configured = (configured_path or "").strip()
    if configured:
        configured_file = Path(configured).expanduser()
        if configured_file.is_dir():
            search_roots.append(configured_file)
        else:
            if configured_file.exists():
                return configured_file
            search_roots.append(configured_file.parent)
    search_roots.extend([edge_build_dir, edge_dist_dir])

    for root in search_roots:
        candidate = root / filename
        if candidate.exists() and candidate.is_file():
            return candidate

    if not requested_os and not requested_arch:
        generic_candidates = [
            edge_runtime_artifact_path(configured_path, edge_build_dir, edge_dist_dir),
            edge_build_dir / "autosec-edge",
            edge_dist_dir / "autosec-edge",
        ]
        for candidate in generic_candidates:
            if candidate.exists() and candidate.is_file():
                return candidate

    return search_roots[0] / filename if search_roots else edge_build_dir / filename


def build_edge_install_command(base: str, raw_token: str) -> str:
    script_url = f"{base}/api/edge/install.sh?enrollment_token={quote(raw_token)}"
    return f'curl -fsSL "{script_url}" | bash'

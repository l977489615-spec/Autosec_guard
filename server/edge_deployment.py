from pathlib import Path
from urllib.parse import quote


def resolve_public_edge_api_base(configured_base: str, request_host_url: str) -> str:
    configured = (configured_base or "").strip()
    if configured and "localhost" not in configured and "127.0.0.1" not in configured:
        return configured.rstrip("/")
    return request_host_url.rstrip("/")


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

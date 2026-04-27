#!/usr/bin/env python3
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from edge_deployment import edge_runtime_filename, normalize_edge_arch, normalize_edge_os


SERVER_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SERVER_DIR.parent
DIST_DIR = Path(os.environ.get("AUTOSEC_EDGE_BUILD_DIR", PROJECT_ROOT / "build" / "edge_runtime")).resolve()
BUILD_DIR = SERVER_DIR / ".edge_build"
SPEC_DIR = SERVER_DIR / ".edge_spec"
ENTRYPOINT = SERVER_DIR / "edge_agent.py"
REGISTRY_GENERATOR = SERVER_DIR / "generate_poc_registry.py"


def _generate_poc_registry() -> None:
    subprocess.run([sys.executable, str(REGISTRY_GENERATOR)], check=True)


def _platform_alias_name() -> str:
    os_type = normalize_edge_os(platform.system())
    arch_type = normalize_edge_arch(platform.machine())
    return edge_runtime_filename(os_type, arch_type)


def main() -> int:
    pyinstaller = shutil.which("pyinstaller")
    if not pyinstaller:
        print("PyInstaller is required. Install it with: pip install pyinstaller", file=sys.stderr)
        return 1

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    SPEC_DIR.mkdir(parents=True, exist_ok=True)
    _generate_poc_registry()

    cmd = [
        pyinstaller,
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "autosec-edge",
        "--distpath",
        str(DIST_DIR),
        "--workpath",
        str(BUILD_DIR),
        "--specpath",
        str(SPEC_DIR),
        "--hidden-import",
        "sandbox_runner",
        "--hidden-import",
        "edge_capability_probe",
        "--hidden-import",
        "poc_worker",
        "--hidden-import",
        "poc_registry",
        "--hidden-import",
        "generated_poc_registry",
        "--collect-all",
        "scapy",
        "--collect-all",
        "can",
        "--collect-all",
        "paramiko",
        "--collect-all",
        "requests",
        str(ENTRYPOINT),
    ]

    subprocess.run(cmd, check=True)
    artifact = DIST_DIR / ("autosec-edge.exe" if os.name == "nt" else "autosec-edge")
    alias_path = DIST_DIR / _platform_alias_name()
    if artifact.exists() and alias_path != artifact:
        shutil.copy2(artifact, alias_path)
    print(f"Built edge runtime: {artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

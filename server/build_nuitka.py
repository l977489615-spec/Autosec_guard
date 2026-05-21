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
ENTRYPOINT = SERVER_DIR / "edge_agent.py"
REGISTRY_GENERATOR = SERVER_DIR / "generate_poc_registry.py"


def _generate_poc_registry() -> None:
    subprocess.run([sys.executable, str(REGISTRY_GENERATOR)], check=True)


def main() -> int:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    _generate_poc_registry()

    os_type = normalize_edge_os(platform.system())
    arch_type = normalize_edge_arch(platform.machine())
    output_filename = edge_runtime_filename(os_type, arch_type)

    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        "--onefile",
        "--assume-yes-for-downloads",
        "--disable-cache=all",
        f"--output-dir={DIST_DIR}",
        f"--output-filename={output_filename}",
        "--include-module=sandbox_runner",
        "--include-module=edge_capability_probe",
        "--include-module=poc_worker",
        "--include-module=poc_registry",
        "--include-module=generated_poc_registry",
        "--include-package=scapy",
        "--include-package=can",
        "--include-package=paramiko",
        "--include-package=requests",
        "--include-package=cryptography",
        "--include-package=bcrypt",
        "--include-package=jwt",
        str(ENTRYPOINT),
    ]

    print(f"[*] Building Edge Agent for {os_type}-{arch_type} using Nuitka...")
    print(f"[*] Command: {' '.join(cmd)}")
    
    subprocess.run(cmd, check=True)
    
    artifact = DIST_DIR / output_filename
    generic_alias = DIST_DIR / ("autosec-edge.exe" if os_type == "windows" else "autosec-edge")
    if artifact.exists() and generic_alias != artifact:
        shutil.copy2(artifact, generic_alias)
    print(f"\n[+] Successfully built obfuscated edge runtime: {artifact}")
    print("[+] Ready for commercial deployment via Thin Edge mechanism.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

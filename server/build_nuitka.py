#!/usr/bin/env python3
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


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

    # Determine OS and Arch
    raw_os = platform.system().lower()
    if raw_os == "darwin" or raw_os == "mac":
        os_type = "darwin"
    elif raw_os == "windows":
        os_type = "windows"
    else:
        os_type = raw_os

    raw_arch = platform.machine().lower()
    if raw_arch in ("x86_64", "amd64"):
        arch_type = "x86_64"
    elif raw_arch in ("aarch64", "arm64", "arm"):
        arch_type = "arm64"
    else:
        arch_type = raw_arch

    output_filename = f"autosec-edge-{os_type}-{arch_type}"
    if os_type == "windows":
        output_filename += ".exe"

    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        "--onefile",
        "--assume-yes-for-downloads",
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

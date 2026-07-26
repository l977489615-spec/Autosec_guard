#!/usr/bin/env python3
"""Build the vendor-only offline license issuer as a local desktop executable."""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"
OUTPUT = ROOT / "build" / "vendor-license-issuer"


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    name = "autosec-license-issuer.exe" if platform.system() == "Windows" else "autosec-license-issuer"
    command = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        "--onefile",
        "--enable-plugin=tk-inter",
        "--lto=yes",
        "--python-flag=no_docstrings",
        "--python-flag=no_asserts",
        "--assume-yes-for-downloads",
        f"--output-dir={OUTPUT}",
        f"--output-filename={name}",
        str(SERVER / "license_issuer_gui.py"),
    ]
    print("[issuer-build] Building vendor-only executable; no private key is embedded.")
    subprocess.run(command, cwd=SERVER, check=True)
    print(f"[issuer-build] Output directory: {OUTPUT}")
    print("[issuer-build] Keep this executable and the encrypted private key off customer media.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

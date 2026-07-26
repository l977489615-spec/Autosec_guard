#!/usr/bin/env python3
"""
Build AutoSec Guard Edge Workstation as a local test-edge distribution.

The distribution is designed for customer delivery: React sources and Python
sources are not copied into the release directory. The Flask workstation service
is compiled into one executable and serves the prebuilt frontend bundle.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
SERVER_DIR = PROJECT_ROOT / "server"
CLIENT_DIR = PROJECT_ROOT / "client"
BUILD_DIR = PROJECT_ROOT / "build" / "edge_workstation"
RELEASE_ROOT = BUILD_DIR / "release"
CLIENT_DIST = CLIENT_DIR / "dist"
POC_WORDLISTS_DIR = SERVER_DIR / "pocs" / "wordlists"
ENTRYPOINT = SERVER_DIR / "server.py"
REGISTRY_GENERATOR = SERVER_DIR / "generate_poc_registry.py"
LICENSE_PUBLIC_KEY_MODULE = SERVER_DIR / "generated_license_public_key.py"
FORBIDDEN_RELEASE_SUFFIXES = {".py", ".pyc", ".pyo", ".map", ".ts", ".tsx"}


def _run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("[build] " + " ".join(cmd))
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, check=True)


def _platform_tag() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {"darwin": "macos", "windows": "windows"}.get(system, system)
    arch = "arm64" if machine in {"arm64", "aarch64"} else "x64" if machine in {"x86_64", "amd64"} else machine
    return f"{os_name}-{arch}"


def _exe_name() -> str:
    return "autosec-guard-edge.exe" if platform.system().lower() == "windows" else "autosec-guard-edge"


def _write_release_files(release_dir: Path, exe_name: str) -> None:
    env_template = """# AutoSec Guard Edge Workstation runtime configuration
# Copy this file to .env before starting the workstation.

AUTOSEC_HOST=127.0.0.1
AUTOSEC_PORT=5002
AUTOSEC_DEBUG=false

# Session and AI-encryption keys are generated once in AUTOSEC_DATA_DIR.
# AUTOSEC_SECRET_KEY=
# AUTOSEC_AI_CONFIG_KEY=

# Optional. Defaults to a per-user application data directory.
# AUTOSEC_DATA_DIR=/opt/autosec-guard-edge/data

# Optional custom location for the signed offline license.
# AUTOSEC_LICENSE_PATH=/opt/autosec-guard-edge/license.autosec

# Optional sandbox limits.
SANDBOX_CPU_SECONDS=60
SANDBOX_MEMORY_MB=256
SANDBOX_OUTPUT_MB=8
SANDBOX_NOFILE=256

# High-risk local exploit binaries remain disabled in customer packages unless
# an administrator explicitly enables them on an isolated lab workstation.
AUTOSEC_ENABLE_HOST_EXPLOITS=false
"""
    (release_dir / ".env.template").write_text(env_template, encoding="utf-8")

    readme = f"""# AutoSec Guard Edge Workstation Runtime

This directory is the customer-facing edge-side distribution.

## Start

macOS / Linux:

```bash
./{exe_name}
```

Windows PowerShell:

```powershell
.\\{exe_name}
```

Then open:

```text
http://127.0.0.1:5002
```

Before starting, verify the adjacent checksum file from the directory that
contains the ZIP. On macOS or Linux:

```bash
shasum -a 256 -c {release_dir.name}.zip.sha256
```

On first use, sign in and copy the device code shown on the license activation
page. Send that code to your AutoSec supplier, then import the returned signed
`.autosec` license file. Renewals only require a new license file; the program
does not need to be reinstalled.

## Customer-owned AI configuration

After login, open Profile and enter the model Base URL, API key, and model
names. The API key is encrypted in the local customer data directory, is never
returned by profile APIs, and is sent only to the model endpoint configured by
the customer. The AutoSec supplier is not in that request path. A cloud model
provider will necessarily receive the key and submitted prompts; use a
customer-hosted local model endpoint when data must remain fully on premises.

## Delivery Boundary

- `client/src` is not included.
- `server/*.py` is not included.
- Built-in PoC code is embedded into the compiled workstation executable.
- Logs and the SQLite database are written to `AUTOSEC_DATA_DIR` or the OS user data directory.

The first launch creates durable per-installation session and AI-encryption keys
inside the user data directory. Back up that directory with the database.
"""
    (release_dir / "README_RUNTIME.md").write_text(readme, encoding="utf-8")

    if platform.system().lower() == "windows":
        launcher = f"""$ErrorActionPreference = "Stop"
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $PSScriptRoot
& ".\\{exe_name}"
"""
        (release_dir / "start.ps1").write_text(launcher, encoding="utf-8")
    else:
        launcher = f"""#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec "./{exe_name}"
"""
        start_path = release_dir / "start.sh"
        start_path.write_text(launcher, encoding="utf-8")
        start_path.chmod(0o755)


def _build_frontend() -> None:
    npm_cmd = "npm.cmd" if platform.system().lower() == "windows" else "npm"
    _run([npm_cmd, "run", "build"], cwd=CLIENT_DIR)


def _generate_registry() -> None:
    _run([sys.executable, str(REGISTRY_GENERATOR)], cwd=SERVER_DIR)


def _validate_license_public_key() -> None:
    """Fail a customer build if its embedded verifier key is absent or malformed."""
    try:
        tree = ast.parse(LICENSE_PUBLIC_KEY_MODULE.read_text(encoding="utf-8"))
        public_b64 = ""
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "LICENSE_PUBLIC_KEY_B64"
                for target in node.targets
            ):
                public_b64 = str(ast.literal_eval(node.value))
                break
        raw = base64.b64decode(public_b64, validate=True)
        if len(raw) != 32:
            raise ValueError
    except (OSError, SyntaxError, ValueError, TypeError) as exc:
        raise RuntimeError(
            "A valid Ed25519 public license key is required before customer packaging. "
            "Run server/license_cli.py generate-keypair first."
        ) from exc


def _copy_runtime_resources(release_dir: Path) -> None:
    if POC_WORDLISTS_DIR.exists():
        destination = release_dir / "pocs" / "wordlists"
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(POC_WORDLISTS_DIR, destination)


def _verify_release_boundary(release_dir: Path) -> None:
    """Fail closed if source, maps, private keys, or local data enter a package."""
    findings: list[str] = []
    for path in release_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(release_dir).as_posix()
        lowered = path.name.lower()
        if path.suffix.lower() in FORBIDDEN_RELEASE_SUFFIXES:
            findings.append(f"source/debug artifact: {relative}")
        if lowered in {".env", ".env.local"} or lowered.endswith((".db", ".db-wal", ".db-shm")):
            findings.append(f"runtime data or secret configuration: {relative}")
        try:
            prefix = path.read_bytes()[:8192]
        except OSError:
            continue
        private_marker = b"-----BEGIN " + b"PRIVATE KEY-----"
        encrypted_marker = b"-----BEGIN ENCRYPTED " + b"PRIVATE KEY-----"
        if private_marker in prefix or encrypted_marker in prefix:
            findings.append(f"private key material: {relative}")
    if findings:
        raise RuntimeError("customer release boundary violation:\n- " + "\n- ".join(sorted(findings)))


def _build_with_nuitka(work_dir: Path, output_name: str) -> Path:
    out_dir = work_dir / "nuitka"
    cache_dir = work_dir / "nuitka-cache"
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    nuitka_mode = os.environ.get("AUTOSEC_NUITKA_MODE", "onefile").strip().lower()
    if nuitka_mode not in {"standalone", "onefile"}:
        raise RuntimeError("AUTOSEC_NUITKA_MODE must be 'standalone' or 'onefile'")
    nuitka_jobs = os.environ.get("AUTOSEC_NUITKA_JOBS", "1").strip() or "1"
    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        "--low-memory",
        f"--jobs={nuitka_jobs}",
        "--lto=yes",
        "--python-flag=no_docstrings",
        "--python-flag=no_asserts",
        "--assume-yes-for-downloads",
        f"--output-dir={out_dir}",
        f"--output-filename={output_name}",
        f"--include-data-dir={CLIENT_DIST}=web_dist",
        f"--include-data-dir={POC_WORDLISTS_DIR}=pocs/wordlists",
        "--include-module=sandbox_runner",
        "--include-module=local_capability_probe",
        "--include-module=poc_worker",
        "--include-module=poc_registry",
        "--include-module=generated_poc_registry",
        "--include-module=poc_security",
        "--include-module=poc_catalog",
        "--include-module=local_requirements",
        "--include-module=config",
        "--include-module=licensing",
        "--include-module=generated_license_public_key",
        "--include-module=assessment_engine",
        "--include-module=benchmark_suite",
        "--include-module=logging.config",
        "--include-module=poc_execution_service",
        "--include-module=agent_orchestrator",
        "--include-module=physical_safety_monitor",
        "--include-module=topology_scanner",
        "--include-module=scapy.all",
        "--include-module=scapy.layers.dot11",
        "--include-module=scapy.layers.inet",
        "--include-module=scapy.layers.l2",
        "--include-module=can",
        "--include-module=can.interfaces.pcan.pcan",
        "--include-module=can.interfaces.socketcan.socketcan",
        "--include-module=can.interfaces.slcan",
        "--include-module=can.interfaces.serial",
        "--include-module=paramiko",
        "--include-module=requests",
        "--include-module=waitress",
        "--include-module=cryptography",
        "--include-module=bcrypt",
        "--nofollow-import-to=openai",
        "--nofollow-import-to=PIL",
        "--nofollow-import-to=MySQLdb",
        "--nofollow-import-to=matplotlib",
        "--nofollow-import-to=numpy",
        "--nofollow-import-to=pandas",
        "--nofollow-import-to=scipy",
        "--nofollow-import-to=tensorflow",
        "--nofollow-import-to=torch",
        "--nofollow-import-to=torchvision",
        "--nofollow-import-to=tkinter",
        str(ENTRYPOINT),
    ]
    if os.environ.get("AUTOSEC_NUITKA_SHOW_MEMORY", "").strip().lower() in {"1", "true", "yes", "on"}:
        cmd.insert(8, "--show-memory")
    if nuitka_mode == "onefile":
        cmd.insert(4, "--onefile")
    env = os.environ.copy()
    env["NUITKA_CACHE_DIR"] = str(cache_dir)
    _run(cmd, cwd=SERVER_DIR, env=env)

    candidates = [
        out_dir / output_name,
        out_dir / f"{ENTRYPOINT.stem}.dist" / output_name,
        out_dir / f"{ENTRYPOINT.stem}.dist" / f"{output_name}.exe",
    ]
    if platform.system().lower() == "windows":
        candidates.extend([
            out_dir / output_name.removesuffix(".exe") / output_name,
            out_dir / f"{ENTRYPOINT.stem}.dist" / output_name.removesuffix(".exe"),
        ])
    for candidate in candidates:
        if candidate.exists():
            return candidate
    matches = sorted(out_dir.rglob(output_name))
    if matches:
        return matches[0]
    raise RuntimeError(f"Nuitka build completed but executable was not found under {out_dir}")


def _pyinstaller_mode() -> str:
    """Return the PyInstaller bundle mode for this build.

    GitHub-hosted Windows and ARM64 runners are slow at the final onefile
    assembly/compression step. The release artifact is already a zip directory,
    so onedir is a better CI default: it keeps the same user-facing launcher
    name while avoiding the timeout-prone onefile packing stage.
    """
    configured = os.environ.get("AUTOSEC_PYINSTALLER_MODE", "").strip().lower()
    if configured in {"onefile", "onedir"}:
        return configured
    return "onedir"


def _build_with_pyinstaller(work_dir: Path, output_name: str) -> Path:
    pyinstaller = shutil.which("pyinstaller")
    if not pyinstaller:
        raise RuntimeError("PyInstaller is required. Install it with: pip install pyinstaller")

    mode = _pyinstaller_mode()
    dist_dir = work_dir / "pyinstaller-dist"
    spec_dir = work_dir / "pyinstaller-spec"
    build_dir = work_dir / "pyinstaller-build"
    cache_dir = work_dir / "pyinstaller-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    sep = ";" if platform.system().lower() == "windows" else ":"
    cmd = [
        pyinstaller,
        "--noconfirm",
        "--clean",
        f"--{mode}",
        "--name",
        output_name.removesuffix(".exe"),
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(build_dir),
        "--specpath",
        str(spec_dir),
        "--add-data",
        f"{CLIENT_DIST}{sep}web_dist",
        "--add-data",
        f"{POC_WORDLISTS_DIR}{sep}pocs/wordlists",
        "--add-data",
        f"{SERVER_DIR / 'migrations'}{sep}migrations",
        "--hidden-import",
        "sandbox_runner",
        "--hidden-import",
        "local_capability_probe",
        "--hidden-import",
        "poc_worker",
        "--hidden-import",
        "poc_registry",
        "--hidden-import",
        "generated_poc_registry",
        "--hidden-import",
        "poc_security",
        "--hidden-import",
        "poc_catalog",
        "--hidden-import",
        "local_requirements",
        "--hidden-import",
        "config",
        "--hidden-import",
        "licensing",
        "--hidden-import",
        "generated_license_public_key",
        "--hidden-import",
        "assessment_engine",
        "--hidden-import",
        "benchmark_suite",
        "--hidden-import",
        "logging.config",
        "--hidden-import",
        "poc_execution_service",
        "--hidden-import",
        "agent_orchestrator",
        "--hidden-import",
        "physical_safety_monitor",
        "--hidden-import",
        "topology_scanner",
        "--hidden-import",
        "scapy.all",
        "--hidden-import",
        "scapy.layers.dot11",
        "--hidden-import",
        "scapy.layers.inet",
        "--hidden-import",
        "scapy.layers.l2",
        "--hidden-import",
        "can",
        "--hidden-import",
        "can.interfaces.pcan",
        "--hidden-import",
        "can.interfaces.pcan.pcan",
        "--hidden-import",
        "can.interfaces.socketcan",
        "--hidden-import",
        "can.interfaces.socketcan.socketcan",
        "--hidden-import",
        "can.interfaces.slcan",
        "--hidden-import",
        "can.interfaces.serial",
        "--hidden-import",
        "paramiko",
        "--hidden-import",
        "requests",
        "--hidden-import",
        "waitress",
        "--hidden-import",
        "cryptography",
        "--hidden-import",
        "bcrypt",
        "--hidden-import",
        "_cffi_backend",
        "--exclude-module",
        "torch",
        "--exclude-module",
        "torchvision",
        "--exclude-module",
        "tensorflow",
        "--exclude-module",
        "pandas",
        "--exclude-module",
        "scipy",
        "--exclude-module",
        "matplotlib",
        "--exclude-module",
        "PIL",
        "--exclude-module",
        "tkinter",
        str(ENTRYPOINT),
    ]
    env = os.environ.copy()
    env["PYINSTALLER_CONFIG_DIR"] = str(cache_dir)
    _run(cmd, cwd=SERVER_DIR, env=env)
    if mode == "onedir":
        bundle_dir = dist_dir / output_name.removesuffix(".exe")
        executable = bundle_dir / output_name
        if not executable.exists() and platform.system().lower() == "windows":
            executable = bundle_dir / f"{output_name.removesuffix('.exe')}.exe"
        return executable
    return dist_dir / output_name


def build(backend: str) -> Path:
    if backend != "nuitka":
        raise RuntimeError("customer releases must use Nuitka; PyInstaller fallback is prohibited")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    RELEASE_ROOT.mkdir(parents=True, exist_ok=True)
    platform_release = RELEASE_ROOT / f"autosec-guard-edge-{_platform_tag()}"
    if platform_release.exists():
        shutil.rmtree(platform_release)
    platform_release.mkdir(parents=True)

    _validate_license_public_key()
    _build_frontend()
    _generate_registry()

    output_name = _exe_name()
    work_dir = BUILD_DIR / _platform_tag()
    work_dir.mkdir(parents=True, exist_ok=True)

    built_with_nuitka = False
    executable = _build_with_nuitka(work_dir, output_name)
    built_with_nuitka = True

    if (
        built_with_nuitka
            and os.environ.get("AUTOSEC_NUITKA_MODE", "onefile").strip().lower() == "standalone"
            and executable.parent.name.endswith(".dist")
    ):
        bundle_dir = executable.parent
        for child in bundle_dir.iterdir():
            destination = platform_release / child.name
            if child.is_dir():
                shutil.copytree(child, destination)
            else:
                shutil.copy2(child, destination)
        release_executable = platform_release / executable.name
        if executable.name != output_name:
            release_executable.rename(platform_release / output_name)
    else:
        shutil.copy2(executable, platform_release / output_name)
    if platform.system().lower() != "windows":
        (platform_release / output_name).chmod(0o755)
    _copy_runtime_resources(platform_release)
    _write_release_files(platform_release, output_name)
    _verify_release_boundary(platform_release)

    archive = shutil.make_archive(str(platform_release), "zip", platform_release)
    archive_path = Path(archive)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
    checksum_path.write_text(f"{digest}  {archive_path.name}\n", encoding="ascii")
    print(f"[build] Release directory: {platform_release}")
    print(f"[build] Release archive: {archive}")
    print(f"[build] SHA-256 checksum: {checksum_path}")
    return platform_release


def main() -> int:
    parser = argparse.ArgumentParser(description="Build AutoSec Guard Edge Workstation release package.")
    parser.add_argument(
        "--backend",
        choices=["nuitka"],
        default=os.environ.get("AUTOSEC_PACKAGER", "nuitka"),
        help="Compiler backend. Customer releases use Nuitka onefile mode by default.",
    )
    args = parser.parse_args()
    build(args.backend)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

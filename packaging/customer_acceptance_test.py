#!/usr/bin/env python3
"""Black-box customer acceptance test for a signed AutoSec release ZIP.

Run only on the vendor acceptance machine. A compatible encrypted issuer key is
required to exercise the real device-code and activation path, but is never
copied into the extracted customer package or included in the report.
"""

from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import http.client
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
from license_cli import issue  # noqa: E402
from licensing import ALL_FEATURES  # noqa: E402


class MockAiHandler(http.server.BaseHTTPRequestHandler):
    authorization = ""
    requests_seen = 0

    def _respond(self) -> None:
        type(self).authorization = self.headers.get("Authorization", "")
        type(self).requests_seen += 1
        body = json.dumps({
            "id": "customer-local-mock",
            "choices": [{"message": {"role": "assistant", "content": "pong"}}],
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_POST = _respond
    do_HEAD = _respond
    do_GET = _respond

    def log_message(self, _format: str, *_args: object) -> None:
        return


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def verify_checksum(package: Path) -> None:
    checksum = package.with_suffix(package.suffix + ".sha256")
    if not checksum.exists():
        raise RuntimeError(f"missing release checksum: {checksum}")
    expected = checksum.read_text(encoding="ascii").split()[0]
    actual = hashlib.sha256(package.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError("release SHA-256 mismatch")


def locate_executable(root: Path) -> Path:
    names = {"autosec-guard-edge", "autosec-guard-edge.exe"}
    matches = [path for path in root.rglob("*") if path.is_file() and path.name in names]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one customer executable, found {len(matches)}")
    executable = matches[0]
    if os.name != "nt":
        executable.chmod(executable.stat().st_mode | 0o700)
    return executable


def assert_release_boundary(root: Path) -> None:
    forbidden = {".py", ".pyc", ".pyo", ".map", ".ts", ".tsx", ".db", ".db-wal", ".db-shm", ".pem"}
    findings = [
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in forbidden
    ]
    if findings:
        raise RuntimeError("customer package contains forbidden files: " + ", ".join(findings))


class CustomerClient:
    def __init__(self, port: int):
        self.base = f"http://127.0.0.1:{port}"
        self.origin = self.base
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def request(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers.update({"Content-Type": "application/json", "Origin": self.origin})
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=90)
            status = response.status
            body = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read()
        return status, json.loads(body.decode("utf-8")) if body else {}


def wait_for_health(port: int, process: subprocess.Popen, timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"customer process exited during startup with code {process.returncode}")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            response.read()
            if response.status == 200:
                return
        except Exception:
            time.sleep(0.5)
        finally:
            connection.close()
    raise RuntimeError("customer package did not become healthy")


def start_customer(executable: Path, data_dir: Path, port: int, log_handle) -> subprocess.Popen:
    inherited = {
        "PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP",
        "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SYSTEMROOT", "WINDIR",
        "COMSPEC", "PATHEXT", "SSL_CERT_FILE", "SSL_CERT_DIR",
    }
    # Simulate a clean customer workstation. In particular, never inherit the
    # repository's .env-derived database, AI, proxy, or signing configuration.
    env = {key: value for key, value in os.environ.items() if key in inherited}
    env.update({
        "AUTOSEC_DATA_DIR": str(data_dir),
        "AUTOSEC_HOST": "127.0.0.1",
        "AUTOSEC_PORT": str(port),
        "AUTOSEC_ALLOW_PRIVATE_AI_URL": "true",
        "PYTHONUNBUFFERED": "1",
    })
    process = subprocess.Popen(
        [str(executable)],
        cwd=executable.parent,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    wait_for_health(port, process)
    return process


def stop_customer(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def assert_secret_absent(secret: str, roots: list[Path]) -> None:
    needle = secret.encode("utf-8")
    for root in roots:
        paths = root.rglob("*") if root.is_dir() else [root]
        for path in paths:
            if path.is_file() and needle in path.read_bytes():
                raise RuntimeError(f"customer AI key leaked in plaintext to {path}")


def run(args: argparse.Namespace) -> dict:
    verify_checksum(args.package)
    MockAiHandler.authorization = ""
    MockAiHandler.requests_seen = 0
    password = os.environ.get("AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD", "")
    password_file = os.environ.get("AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD_FILE", "").strip()
    if not password and password_file:
        password = Path(password_file).expanduser().read_text(encoding="utf-8").strip()
    if not password:
        raise RuntimeError("issuer password or AUTOSEC_LICENSE_PRIVATE_KEY_PASSWORD_FILE is required")
    results: dict[str, object] = {"package": args.package.name, "checks": []}
    checks: list[str] = results["checks"]  # type: ignore[assignment]

    with tempfile.TemporaryDirectory(prefix="autosec-customer-e2e-") as temp:
        workspace = Path(temp)
        install_dir = workspace / "installed"
        data_dir = workspace / "customer-data"
        install_dir.mkdir()
        data_dir.mkdir()
        with zipfile.ZipFile(args.package) as archive:
            archive.extractall(install_dir)
        executable = locate_executable(install_dir)
        assert_release_boundary(install_dir)
        checks.extend(["sha256_verified", "installed_from_zip", "no_source_or_private_key_in_package"])

        ai_port = free_port()
        ai_server = http.server.ThreadingHTTPServer(("127.0.0.1", ai_port), MockAiHandler)
        ai_thread = threading.Thread(target=ai_server.serve_forever, daemon=True)
        ai_thread.start()
        app_port = free_port()
        log_path = workspace / "customer-runtime.log"
        customer_api_key = "customer-local-only-" + os.urandom(20).hex()
        process = None
        with log_path.open("ab") as log_handle:
            try:
                process = start_customer(executable, data_dir, app_port, log_handle)
                client = CustomerClient(app_port)
                status, registration = client.request("POST", "/api/v1/auth/register", {
                    "username": "customer-admin",
                    "password": "customer-acceptance-password-2026",
                })
                if status != 201:
                    raise RuntimeError(f"first-run registration failed: HTTP {status}: {registration}")
                status, login = client.request("POST", "/api/v1/auth/login", {
                    "username": "customer-admin",
                    "password": "customer-acceptance-password-2026",
                })
                if status != 200 or "token" in login:
                    raise RuntimeError("browser login contract failed")
                checks.extend(["first_run_bootstrap", "secure_cookie_login"])

                status, missing = client.request("GET", "/api/v1/license/status")
                if status != 200 or missing.get("state") != "missing" or not missing.get("machine_code"):
                    raise RuntimeError(f"missing-license state failed: {missing}")
                status, denied = client.request("POST", "/api/v1/sessions", {
                    "mode": "manual", "target": {"ip": "127.0.0.1"},
                })
                if status != 403 or denied.get("error", {}).get("code") != "LICENSE_REQUIRED":
                    raise RuntimeError("unlicensed scan was not blocked")
                checks.append("unlicensed_scan_blocked")

                license_path = workspace / "customer-license.autosec"
                issue(argparse.Namespace(
                    private_key=args.issuer_key,
                    customer="Black-box Acceptance Customer",
                    machine_code=missing["machine_code"],
                    months=3,
                    days=None,
                    expires_at=None,
                    not_before=None,
                    license_id="LIC-E2E-ACCEPTANCE",
                    edition="enterprise",
                    features=",".join(sorted(ALL_FEATURES)),
                    key_id="acceptance-key",
                    output=license_path,
                ), password=password.encode("utf-8"))
                license_document = json.loads(license_path.read_text(encoding="utf-8"))
                status, activated = client.request("POST", "/api/v1/license/activate", {"license": license_document})
                if status != 201 or not activated.get("valid"):
                    raise RuntimeError(f"license activation failed: HTTP {status}: {activated}")
                checks.extend(["device_code_issued", "three_month_license_signed", "license_activated"])

                ai_payload = {
                    "ai_config": {
                        "base_url": f"http://127.0.0.1:{ai_port}/v1",
                        "api_key": customer_api_key,
                        "fast_model": "customer-local-model",
                        "report_model": "customer-local-model",
                        "strong_model": "customer-local-model",
                    }
                }
                status, profile = client.request("PUT", "/api/v1/profile", ai_payload)
                serialized = json.dumps(profile, ensure_ascii=False)
                if status != 200 or customer_api_key in serialized:
                    raise RuntimeError("AI key was returned by profile update")
                status, profile = client.request("GET", "/api/v1/profile")
                ai_config = profile.get("user", {}).get("ai_config", {})
                if status != 200 or ai_config.get("apiKey") or not ai_config.get("apiKeyConfigured"):
                    raise RuntimeError("masked AI configuration contract failed")
                status, ai_test = client.request("POST", "/api/v1/test-ai-config", {
                    "ai_config": {"fast_model": "customer-local-model"}
                })
                if status != 200 or not ai_test.get("success"):
                    raise RuntimeError(f"customer-local AI test failed: {ai_test}")
                if MockAiHandler.authorization != f"Bearer {customer_api_key}":
                    raise RuntimeError("saved local AI key was not used for provider request")
                checks.extend(["ai_key_saved_locally", "ai_key_masked_from_api", "local_ai_provider_called"])

                status, created = client.request("POST", "/api/v1/sessions", {
                    "mode": "manual",
                    "target": {"name": "customer-local-mock", "ip": "127.0.0.1"},
                    "policy": {"max_tier": "PASSIVE"},
                })
                if status != 201:
                    raise RuntimeError(f"licensed session creation failed: {created}")
                session_id = created["session"]["id"]
                status, _ = client.request("POST", f"/api/v1/sessions/{session_id}/runs", {"action": "start"})
                if status != 202:
                    raise RuntimeError("session start failed")
                status, poc = client.request("POST", "/api/v1/run_poc", {
                    "filename": "network/15_CWE_200_Service_Probe_Active_Validation.py",
                    "session_id": session_id,
                    "params": {
                        "target_ip": "127.0.0.1",
                        "target_port": ai_port,
                        "probe_profiles": ["http_head"],
                    },
                })
                if status != 200 or not poc.get("success") or poc.get("vulnerable") is not False or not poc.get("evidence"):
                    raise RuntimeError(f"safe detection failed: HTTP {status}: {poc}")
                status, completed = client.request(
                    "POST", f"/api/v1/sessions/{session_id}/runs", {"action": "complete", "result": poc}
                )
                if status != 200 or completed.get("session", {}).get("status") != "completed":
                    raise RuntimeError("session completion/persistence failed")
                checks.extend(["licensed_scan_session", "safe_local_detection", "result_persisted"])

                stop_customer(process)
                process = start_customer(executable, data_dir, app_port, log_handle)
                client = CustomerClient(app_port)
                status, _ = client.request("POST", "/api/v1/auth/login", {
                    "username": "customer-admin",
                    "password": "customer-acceptance-password-2026",
                })
                if status != 200:
                    raise RuntimeError("login after restart failed")
                status, license_status = client.request("GET", "/api/v1/license/status")
                if status != 200 or not license_status.get("valid"):
                    raise RuntimeError("license did not persist across restart")
                status, profile = client.request("GET", "/api/v1/profile")
                if status != 200 or not profile.get("user", {}).get("ai_config", {}).get("apiKeyConfigured"):
                    raise RuntimeError("encrypted AI configuration did not persist")
                status, sessions = client.request("GET", "/api/v1/sessions")
                if status != 200 or not any(item.get("id") == session_id for item in sessions.get("sessions", [])):
                    raise RuntimeError("scan result did not persist")
                checks.extend(["restart_success", "license_persisted", "encrypted_ai_config_persisted", "scan_history_persisted"])
            finally:
                if process is not None and process.poll() is None:
                    stop_customer(process)
                ai_server.shutdown()
                ai_server.server_close()

        assert_secret_absent(customer_api_key, [data_dir, log_path, install_dir])
        checks.append("ai_key_absent_from_files_logs_and_package")
        results.update({
            "ok": True,
            "check_count": len(checks),
            "ai_requests_seen": MockAiHandler.requests_seen,
            "license_id": "LIC-E2E-ACCEPTANCE",
        })
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Run black-box acceptance against a customer release ZIP.")
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--issuer-key", type=Path, required=True)
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "build" / "customer-acceptance-report.json",
    )
    args = parser.parse_args()
    report = run(args)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

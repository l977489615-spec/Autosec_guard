"""probe_utils.py – Product-grade probe utilities for the AutoSec vulnerability scanner.

Provides four core capabilities required for commercial-scanner-grade detection:
  1. TLS fingerprinting  – identify service version from TLS handshake behaviour
  2. Semantic version comparison – precise range checking (not string matching)
  3. HTTP behavioral probes – endpoint-specific request/response analysis
  4. ADB integration – Android device interrogation via adb
  5. Detection confidence scoring – standardise evidence quality reporting

Detection levels (aligned with Nessus / Greenbone / Qualys taxonomy):
  A  – Behavioral confirmed: payload triggered & characteristic effect observed
  B  – Functional probe:     CVE-specific payload sent, response matches vuln signature
  C  – Version + config:     exact version AND prerequisite config both verified
  D  – Version only:         version in affected range, config not verified  (FP risk: medium)
  E  – Passive / banner:     version from banner/header only  (FP risk: high)
  HW – Hardware required:    BT/CAN/RF hardware not present; cannot assess remotely
"""
from __future__ import annotations

import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# 1. Semantic version comparison
# ---------------------------------------------------------------------------

class Version:
    """Comparable semantic version (major.minor.patch[.build])."""

    def __init__(self, s: str):
        s = s.strip().lstrip("vV")
        parts = re.split(r"[.\-]", s)
        nums = []
        for p in parts:
            try:
                nums.append(int(p))
            except ValueError:
                break
        self.parts = nums or [0]

    def _pad(self, other: "Version") -> Tuple[List[int], List[int]]:
        a, b = list(self.parts), list(other.parts)
        n = max(len(a), len(b))
        a += [0] * (n - len(a))
        b += [0] * (n - len(b))
        return a, b

    def __lt__(self, other: "Version") -> bool:  return self._pad(other)[0] <  self._pad(other)[1]
    def __le__(self, other: "Version") -> bool:  return self._pad(other)[0] <= self._pad(other)[1]
    def __gt__(self, other: "Version") -> bool:  return self._pad(other)[0] >  self._pad(other)[1]
    def __ge__(self, other: "Version") -> bool:  return self._pad(other)[0] >= self._pad(other)[1]
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version): return NotImplemented
        return self._pad(other)[0] == self._pad(other)[1]
    def __str__(self) -> str: return ".".join(str(p) for p in self.parts)
    def __repr__(self) -> str: return f"Version({str(self)!r})"


def version_in_range(
    detected: str,
    ge: Optional[str] = None,
    lt: Optional[str] = None,
    le: Optional[str] = None,
    gt: Optional[str] = None,
    eq: Optional[str] = None,
) -> bool:
    """Return True if *detected* falls within the specified version range.

    Example::
        version_in_range("3.0.2", ge="3.0.0", lt="3.0.3")  # True
        version_in_range("1.1.1p", ge="1.1.1", lt="1.1.1o")  # False
    """
    if not detected:
        return False
    v = Version(detected)
    if ge  and not (v >= Version(ge)):  return False
    if le  and not (v <= Version(le)):  return False
    if gt  and not (v >  Version(gt)):  return False
    if lt  and not (v <  Version(lt)):  return False
    if eq  and not (v == Version(eq)):  return False
    return True


def openssl_version_affected(detected: str, cve: str) -> Optional[bool]:
    """Return True/False/None for known OpenSSL CVE version ranges.

    None means the version string could not be compared precisely.
    """
    RANGES: Dict[str, List[Dict]] = {
        # format: [{ge, lt}, ...] – any match → affected
        "CVE-2022-1292":  [{"ge": "1.0.2", "lt": "1.0.2ze"},
                           {"ge": "1.1.1", "lt": "1.1.1o"},
                           {"ge": "3.0.0", "lt": "3.0.3"}],
        "CVE-2022-2068":  [{"ge": "1.0.2", "lt": "1.0.2zf"},
                           {"ge": "1.1.1", "lt": "1.1.1p"},
                           {"ge": "3.0.0", "lt": "3.0.4"}],
        "CVE-2022-37434": [{"ge": "1.2.11", "lt": "1.2.12"}],   # zlib
        "CVE-2023-29406": [{"ge": "1.20.0", "lt": "1.20.6"}],   # Go HTTP/1.1
        "CVE-2024-6119":  [{"ge": "3.0.0", "lt": "3.0.14"},
                           {"ge": "3.1.0", "lt": "3.1.6"},
                           {"ge": "3.2.0", "lt": "3.2.3"},
                           {"ge": "3.3.0", "lt": "3.3.2"}],
        "CVE-2024-5535":  [{"ge": "1.0.1",  "lt": "3.0.0"},
                           {"ge": "3.0.0",  "lt": "3.0.14"},
                           {"ge": "3.1.0",  "lt": "3.1.6"},
                           {"ge": "3.2.0",  "lt": "3.2.3"},
                           {"ge": "3.3.0",  "lt": "3.3.2"}],
        "CVE-2024-4741":  [{"ge": "3.0.0", "lt": "3.0.14"},
                           {"ge": "3.1.0", "lt": "3.1.6"},
                           {"ge": "3.2.0", "lt": "3.2.3"},
                           {"ge": "3.3.0", "lt": "3.3.2"}],
        "CVE-2024-2511":  [{"ge": "1.0.2", "lt": "1.0.2zj"},
                           {"ge": "3.0.0", "lt": "3.0.14"},
                           {"ge": "3.1.0", "lt": "3.1.6"},
                           {"ge": "3.2.0", "lt": "3.2.3"},
                           {"ge": "3.3.0", "lt": "3.3.2"}],
        "CVE-2024-0727":  [{"ge": "3.0.0", "lt": "3.0.13"},
                           {"ge": "3.1.0", "lt": "3.1.5"},
                           {"ge": "3.2.0", "lt": "3.2.1"}],
    }
    ranges = RANGES.get(cve)
    if not ranges:
        return None
    if not detected:
        return None
    try:
        return any(version_in_range(detected, **r) for r in ranges)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 2. TLS fingerprinting
# ---------------------------------------------------------------------------

def tls_get_server_info(
    host: str,
    port: int = 443,
    timeout: float = 8.0,
    alpn: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Connect via TLS and return server fingerprint information.

    Returns a dict with keys:
      tls_version, cipher, cert_subject, cert_issuer, cert_cn, cert_not_after,
      cert_san, server_header, alpn_negotiated, error
    """
    result: Dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        if alpn:
            ctx.set_alpn_protocols(alpn)
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        tls_sock = ctx.wrap_socket(raw, server_hostname=host)

        result["tls_version"] = tls_sock.version()
        result["cipher"] = tls_sock.cipher()

        cert = tls_sock.getpeercert()
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            result["cert_cn"] = subject.get("commonName", "")
            result["cert_subject"] = str(subject)
            result["cert_issuer"] = str(issuer)
            result["cert_not_after"] = cert.get("notAfter", "")
            san_entries = []
            for kind, value in cert.get("subjectAltName", []):
                san_entries.append(f"{kind}:{value}")
            result["cert_san"] = san_entries

        if alpn:
            result["alpn_negotiated"] = tls_sock.selected_alpn_protocol()

        # Try to get HTTP Server header
        try:
            tls_sock.send(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            tls_sock.settimeout(3.0)
            resp = tls_sock.recv(2048).decode(errors="replace")
            m = re.search(r"Server:\s*(.+)", resp, re.IGNORECASE)
            if m:
                result["server_header"] = m.group(1).strip()
            # Try to extract OpenSSL version from Server header
            m2 = re.search(r"OpenSSL/(\S+)", resp, re.IGNORECASE)
            if m2:
                result["openssl_version_from_header"] = m2.group(1)
        except Exception:
            pass

        tls_sock.close()

    except ssl.SSLError as exc:
        result["ssl_error"] = str(exc)
    except ConnectionRefusedError:
        result["connection_refused"] = True
    except socket.timeout:
        result["timeout"] = True
    except Exception as exc:
        result["error"] = str(exc)

    return result


def detect_openssl_version(host: str, port: int = 443, timeout: float = 8.0) -> Optional[str]:
    """Best-effort OpenSSL version detection via TLS handshake + HTTP header.

    Returns version string like "3.0.2" or None if undetectable.
    """
    info = tls_get_server_info(host, port, timeout)
    # 1. Direct OpenSSL version in Server header (most reliable)
    if info.get("openssl_version_from_header"):
        return info["openssl_version_from_header"]
    # 2. Version mentioned in cert CN or issuer
    for field in [info.get("cert_cn", ""), info.get("cert_issuer", "")]:
        m = re.search(r"OpenSSL[/ ](\d+\.\d+[\.\d]*)", field, re.IGNORECASE)
        if m:
            return m.group(1)
    # 3. Infer from TLS capabilities (heuristic, low confidence)
    tls_ver = info.get("tls_version", "")
    cipher = info.get("cipher", ("", "", ""))
    cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
    if "TLSv1.3" in tls_ver:
        # TLS 1.3 requires OpenSSL 1.1.1+
        info["tls13_capable"] = True
    return None


# ---------------------------------------------------------------------------
# 3. HTTP behavioral probes
# ---------------------------------------------------------------------------

class HTTPProbe:
    """Thin HTTP/HTTPS probe for behavioral checks."""

    def __init__(
        self,
        host: str,
        port: int = 80,
        tls: bool = False,
        timeout: float = 8.0,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
    ):
        self.base = f"{'https' if tls else 'http'}://{host}:{port}"
        self.timeout = timeout
        self.default_headers = headers or {}
        self.follow_redirects = follow_redirects
        self._opener = self._build_opener()

    def _build_opener(self) -> urllib.request.OpenerDirector:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handler = urllib.request.HTTPSHandler(context=ctx)
        if self.follow_redirects:
            return urllib.request.build_opener(handler)
        no_redir = urllib.request.build_opener(handler, _NoRedirectHandler())
        return no_redir

    def request(
        self,
        method: str,
        path: str,
        body: Optional[bytes] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = self.base.rstrip("/") + "/" + path.lstrip("/")
        hdrs = {"User-Agent": "AutosecScanner/1.0", **self.default_headers}
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                content = r.read(8192)
                return {
                    "url": url,
                    "status": r.status,
                    "headers": dict(r.headers),
                    "body": content,
                    "body_text": content.decode(errors="replace"),
                }
        except urllib.error.HTTPError as e:
            try:
                body_data = e.read(4096)
            except Exception:
                body_data = b""
            return {
                "url": url,
                "status": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": body_data,
                "body_text": body_data.decode(errors="replace"),
                "http_error": True,
            }
        except urllib.error.URLError as e:
            return {"url": url, "status": None, "error": str(e.reason)}
        except Exception as exc:
            return {"url": url, "status": None, "error": str(exc)}

    def get(self, path: str, **kw) -> Dict[str, Any]:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: bytes, content_type: str = "application/json", **kw) -> Dict[str, Any]:
        return self.request("POST", path, body=body,
                            extra_headers={"Content-Type": content_type}, **kw)

    def get_server_version(self) -> Optional[str]:
        """Extract server software version from HTTP response headers."""
        r = self.get("/")
        server = r.get("headers", {}).get("Server", "")
        m = re.search(r"(\d+\.\d+[\.\d]*)", server)
        return m.group(1) if m else None


class _NoRedirectHandler(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response
    https_response = http_response


def http_default_creds_probe(
    host: str,
    port: int,
    tls: bool,
    paths: Sequence[str],
    cred_pairs: Sequence[Tuple[str, str]],
    timeout: float = 3.0,
    max_total_seconds: float = 25.0,
) -> Dict[str, Any]:
    """Try default credential pairs against login paths.  Returns first success."""
    import base64, json as _json

    started = time.time()
    result: Dict[str, Any] = {"paths_tried": list(paths), "creds_tried": len(cred_pairs)}
    probe = HTTPProbe(host, port, tls, timeout)

    def _timed_out() -> bool:
        return (time.time() - started) >= max_total_seconds

    def _request_failed(response: Dict[str, Any]) -> bool:
        return response.get("status") is None and bool(response.get("error"))

    consecutive_failures = 0
    for path in paths:
        if _timed_out():
            result["aborted"] = "probe_time_budget_exceeded"
            break
        path_unreachable = False
        for user, passwd in cred_pairs:
            if _timed_out():
                result["aborted"] = "probe_time_budget_exceeded"
                break
            b64 = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            r = probe.request("GET", path, extra_headers={"Authorization": f"Basic {b64}"})
            if _request_failed(r):
                consecutive_failures += 1
                path_unreachable = True
                if consecutive_failures >= 3:
                    result["aborted"] = "connection_failures"
                    result["success"] = False
                    result["elapsed_seconds"] = round(time.time() - started, 2)
                    return result
                break
            consecutive_failures = 0
            if r.get("status") in (200, 302) and r.get("status") != 401:
                result["success"] = True
                result["credential"] = f"{user}:{passwd}"
                result["path"] = path
                result["status"] = r.get("status")
                result["body_preview"] = r.get("body_text", "")[:200]
                result["elapsed_seconds"] = round(time.time() - started, 2)
                return result
            if path_unreachable:
                break
            payload = _json.dumps({"username": user, "password": passwd}).encode()
            r2 = probe.post(path, payload)
            if _request_failed(r2):
                consecutive_failures += 1
                path_unreachable = True
                if consecutive_failures >= 3:
                    result["aborted"] = "connection_failures"
                    result["success"] = False
                    result["elapsed_seconds"] = round(time.time() - started, 2)
                    return result
                break
            consecutive_failures = 0
            if r2.get("status") in (200, 201) and r2.get("status") not in (401, 403):
                body = r2.get("body_text", "")
                if any(k in body.lower() for k in ("token", "session", "success", "welcome", "dashboard")):
                    result["success"] = True
                    result["credential"] = f"{user}:{passwd}"
                    result["path"] = path
                    result["status"] = r2.get("status")
                    result["auth_type"] = "json"
                    result["elapsed_seconds"] = round(time.time() - started, 2)
                    return result
        if result.get("aborted"):
            break
    result["success"] = False
    result["elapsed_seconds"] = round(time.time() - started, 2)
    return result


# ---------------------------------------------------------------------------
# 4. ADB integration
# ---------------------------------------------------------------------------

class ADBProbe:
    """Android device interrogation via adb."""

    def __init__(self, serial: Optional[str] = None, timeout: int = 30):
        self.serial = serial
        self.timeout = timeout
        self._adb_available: Optional[bool] = None

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += list(args)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)

    def available(self) -> bool:
        if self._adb_available is not None:
            return self._adb_available
        try:
            r = subprocess.run(["adb", "version"], capture_output=True, text=True, timeout=5)
            self._adb_available = r.returncode == 0
        except FileNotFoundError:
            self._adb_available = False
        return self._adb_available

    def devices(self) -> List[Dict[str, str]]:
        if not self.available():
            return []
        r = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, timeout=10)
        devs = []
        for line in r.stdout.splitlines()[1:]:
            if line.strip() and "device" in line:
                parts = line.split()
                devs.append({"serial": parts[0], "state": parts[1] if len(parts) > 1 else "unknown"})
        return devs

    def shell(self, command: str) -> str:
        if not self.available():
            return ""
        r = self._run("shell", command)
        return r.stdout.strip()

    def getprop(self, prop: str) -> str:
        return self.shell(f"getprop {prop}")

    def android_version(self) -> str:
        return self.getprop("ro.build.version.release")

    def sdk_version(self) -> Optional[int]:
        v = self.getprop("ro.build.version.sdk")
        try:
            return int(v)
        except ValueError:
            return None

    def package_info(self, package: str) -> str:
        return self.shell(f"dumpsys package {package}")

    def list_packages(self, flags: str = "") -> List[str]:
        out = self.shell(f"pm list packages {flags}")
        return [line.replace("package:", "").strip() for line in out.splitlines() if line.startswith("package:")]

    def pull_file(self, remote: str, local: str) -> bool:
        if not self.available():
            return False
        r = self._run("pull", remote, local)
        return r.returncode == 0

    def device_info(self) -> Dict[str, str]:
        return {
            "android_version": self.android_version(),
            "sdk_version": str(self.sdk_version() or ""),
            "brand": self.getprop("ro.product.brand"),
            "model": self.getprop("ro.product.model"),
            "build_fingerprint": self.getprop("ro.build.fingerprint"),
            "security_patch": self.getprop("ro.build.version.security_patch"),
        }

    def check_debuggable(self) -> bool:
        return self.getprop("ro.debuggable") == "1"

    def check_adb_enabled(self) -> bool:
        return self.getprop("persist.service.adb.enable") == "1"

    def check_app_debuggable(self, package: str) -> Optional[bool]:
        info = self.package_info(package)
        if "pkgFlags" not in info:
            return None
        return "DEBUGGABLE" in info

    def check_app_allowbackup(self, package: str) -> Optional[bool]:
        info = self.package_info(package)
        if not info:
            return None
        return "allowBackup=true" in info or "ALLOW_BACKUP" in info

    def exported_activities(self, package: str) -> List[str]:
        """Return list of exported activity names from dumpsys package."""
        info = self.package_info(package)
        exported = []
        in_activities = False
        for line in info.splitlines():
            if "Activity Resolver Table" in line:
                in_activities = True
            if in_activities and package + "/" in line:
                exported.append(line.strip())
        return exported


# ---------------------------------------------------------------------------
# 5. Detection confidence scoring
# ---------------------------------------------------------------------------

DETECTION_LEVELS = {
    "A": "Behavioral confirmed – CVE effect directly observed",
    "B": "Functional probe – CVE-specific payload, characteristic response matched",
    "C": "Version + config – exact version AND prerequisite config both verified",
    "D": "Version only – version in affected range, config not verified (FP risk: medium)",
    "E": "Passive / banner – version from header only (FP risk: high)",
    "HW": "Hardware required – BT/CAN/RF hardware needed, cannot assess remotely",
}

FP_RISK_BY_LEVEL = {
    "A": "very_low",
    "B": "low",
    "C": "medium",
    "D": "medium_high",
    "E": "high",
    "HW": "unknown",
}

CONFIDENCE_BY_LEVEL = {
    "A": "confirmed",
    "B": "high",
    "C": "medium",
    "D": "low",
    "E": "informational",
    "HW": "hardware_required",
}


def detection_confidence(
    level: str,
    evidence: Dict[str, Any],
    method: str = "",
    extra: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Build a standardised detection_confidence dict to attach to probe results.

    Args:
        level:    One of A / B / C / D / E / HW
        evidence: The evidence dict from the probe
        method:   Short string describing the detection method
        extra:    Additional fields to merge

    Returns dict suitable for embedding in probe result as "detection_confidence".
    """
    result = {
        "level": level,
        "level_description": DETECTION_LEVELS.get(level, level),
        "confidence": CONFIDENCE_BY_LEVEL.get(level, "unknown"),
        "fp_risk": FP_RISK_BY_LEVEL.get(level, "unknown"),
        "method": method or _infer_method(evidence),
        "evidence_keys": [k for k in evidence if k not in ("target", "cve")],
    }
    if extra:
        result.update(extra)
    return result


def _infer_method(evidence: Dict[str, Any]) -> str:
    keys = set(evidence.keys())
    if any(k in keys for k in ("exploited", "crashed", "uid_0", "root_achieved")):
        return "behavioral_exploit"
    if any(k in keys for k in ("crash_observed", "connection_reset", "server_aborted")):
        return "behavioral_crash"
    if any(k in keys for k in ("response_matched", "payload_accepted", "characteristic_response")):
        return "payload_response_match"
    if "tls_version" in keys or "cipher" in keys or "openssl_version_from_header" in keys:
        return "tls_fingerprint"
    if any(k in keys for k in ("http_status", "server_header", "body_preview")):
        return "http_probe"
    if any(k in keys for k in ("adb_serial", "android_version", "sdk_version")):
        return "adb_device_probe"
    if any(k in keys for k in ("version_in_affected_range", "detected_version")):
        return "version_comparison"
    return "unknown"


def score_probe_result(evidence: Dict[str, Any], vulnerable: Optional[bool]) -> Dict[str, Any]:
    """Auto-score a probe result and return detection_confidence dict."""
    keys = set(evidence.keys())

    # Level A: behavioral
    if (vulnerable is True and
            any(k in keys for k in ("exploited", "crash_observed", "connection_reset",
                                     "server_aborted", "uid_0", "root_achieved"))):
        return detection_confidence("A", evidence, _infer_method(evidence))

    # Level B: functional – payload sent + characteristic response
    if any(k in keys for k in ("restore_response", "overflow_response_code",
                                 "recv_data", "traversal_path_used", "wildcard_key_obtained",
                                 "payload_hex", "trigger_payload_sent")):
        return detection_confidence("B", evidence, _infer_method(evidence))

    # Level C: version + TLS/HTTP probe
    if any(k in keys for k in ("tls_version", "openssl_version_from_header",
                                 "server_header", "android_version")):
        return detection_confidence("C", evidence, _infer_method(evidence))

    # Level D: version comparison only
    if any(k in keys for k in ("version_in_affected_range", "detected_version")):
        return detection_confidence("D", evidence, "version_comparison")

    # Level HW: hardware required
    if any(k in keys for k in ("bt_adapter_missing", "hcitool_missing",
                                 "can_socket_unavailable", "sdr_missing")):
        return detection_confidence("HW", evidence, "hardware_probe")

    return detection_confidence("E", evidence, "passive")


# ---------------------------------------------------------------------------
# 6. SSH remote command execution
# ---------------------------------------------------------------------------

def ssh_exec(
    host: str,
    port: int = 22,
    username: str = "root",
    password: Optional[str] = None,
    key_file: Optional[str] = None,
    command: str = "uname -r",
    timeout: int = 15,
) -> Dict[str, Any]:
    """Execute a remote command via SSH and return stdout/stderr/rc."""
    result: Dict[str, Any] = {"host": host, "command": command}
    try:
        import paramiko  # optional dependency
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        kw: Dict[str, Any] = {"hostname": host, "port": port, "username": username,
                               "timeout": timeout, "banner_timeout": timeout}
        if key_file:
            kw["key_filename"] = key_file
        elif password:
            kw["password"] = password
        client.connect(**kw)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        result["stdout"] = stdout.read().decode(errors="replace").strip()
        result["stderr"] = stderr.read().decode(errors="replace").strip()
        result["rc"] = stdout.channel.recv_exit_status()
        client.close()
    except ImportError:
        # Fall back to subprocess ssh if paramiko not available
        try:
            args = ["ssh", "-o", "StrictHostKeyChecking=yes", "-o", f"ConnectTimeout={timeout}",
                    f"{username}@{host}", "-p", str(port), command]
            r = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 5)
            result["stdout"] = r.stdout.strip()
            result["stderr"] = r.stderr.strip()
            result["rc"] = r.returncode
        except Exception as exc:
            result["error"] = str(exc)
    except Exception as exc:
        result["error"] = str(exc)
    return result


# ---------------------------------------------------------------------------
# 7. Quick service availability check
# ---------------------------------------------------------------------------

def service_open(host: str, port: int, timeout: float = 5.0) -> bool:
    """Return True if TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def tcp_banner(host: str, port: int, timeout: float = 5.0, probe: bytes = b"") -> str:
    """Connect to a TCP port and return raw banner bytes as string."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if probe:
                s.sendall(probe)
            return s.recv(1024).decode(errors="replace")
    except Exception:
        return ""

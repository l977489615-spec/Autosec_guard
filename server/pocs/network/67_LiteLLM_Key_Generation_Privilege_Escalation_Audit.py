#!/usr/bin/env python3
"""Safe exposure audit for LiteLLM API key authorization boundary risk."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": "POC-LAB-006",
    "cve": "CVE-2026-47101",
    "year": 2026,
    "domain": "车联网AI服务/开发运维平台",
    "vendor_product": "LiteLLM",
    "component": "/key/generate and /user/update authorization flow",
    "type": "权限提升",
    "summary": "LiteLLM 低权限 internal_user 可通过 API key 路由授权边界缺陷提升为 proxy_admin；车联网 AI 助手、研发运维平台和云端代理服务需排查。",
    "source_description": "poc-lab describes an authorization chain where /key/generate accepts over-broad allowed_routes and /user/update can be used to elevate privileges.",
    "poc_status": "poc-lab公开复现；本插件仅做安全暴露审计",
    "research_value": "车联网安全平台、数据分析平台和研发运维环境可能部署 LiteLLM 作为模型代理，权限提升会影响密钥与管理面。",
    "source_url": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-47101%20LiteLLM",
    "references": ["https://github.com/Unclecheng-li/poc-lab"],
    "affected": [
        {
            "vendor": "LiteLLM",
            "product": "LiteLLM",
            "versions": [{"version": "0", "status": "affected", "lessThan": "1.83.14", "versionType": "semver"}],
        }
    ],
    "active_probe_paths": [
        "/health",
        "/version",
        "/key/generate",
    ],
    "signature_tokens": [
        "CVE-2026-47101", "LiteLLM", "litellm", "1.83.14", "1.82.6",
        "/key/generate", "/user/update", "allowed_routes", "internal_user",
        "proxy_admin", "Incorrect Authorization",
    ],
}


class LiteLLMKeyGenerationPrivilegeEscalationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-067"
    meta_poc_name = "LiteLLM Key Generation Privilege Escalation Audit"
    meta_cve_id = "CVE-2026-47101"
    meta_severity = "High"
    meta_protocol = "http"
    meta_target_os = ["linux", "all"]
    meta_required_params = ["service_banner"]
    meta_profiles = ["network", "backend", "ai"]
    meta_source_url = VULN["source_url"]
    meta_attack_surface = "车联网AI服务/开发运维平台"
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

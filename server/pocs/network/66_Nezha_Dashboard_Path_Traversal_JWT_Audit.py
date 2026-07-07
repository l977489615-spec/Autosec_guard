#!/usr/bin/env python3
"""Safe exposure audit for Nezha dashboard traversal and JWT secret leakage."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": "POC-LAB-005",
    "cve": "CVE-2026-53519",
    "year": 2026,
    "domain": "车联网运维监控/边缘节点",
    "vendor_product": "Nezha Monitoring",
    "component": "Dashboard fallbackToFrontend / config.yaml",
    "type": "路径遍历/JWT伪造",
    "summary": "Nezha Monitoring Dashboard 路径前缀判断缺陷可能泄露 config.yaml 与 JWT 密钥，进而接管管理后台；车联网边缘节点与运维监控平台需排查。",
    "source_description": "poc-lab documents unauthenticated path traversal via /dashboard../data/config.yaml leading to jwt_secret_key leakage and administrator takeover.",
    "poc_status": "poc-lab公开复现；本插件仅做安全暴露审计",
    "research_value": "哪吒监控常用于服务器/边缘节点观测，若被用于车联网研发、云边协同或测试台架，属于高危管理面风险。",
    "source_url": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-53519%20Nezha%20Monitoring",
    "references": [
        "https://github.com/Unclecheng-li/poc-lab",
        "https://github.com/nezhahq/nezha/security/advisories/GHSA-5c25-7vpj-9mqh",
    ],
    "affected": [
        {
            "vendor": "Nezha",
            "product": "Nezha Monitoring",
            "versions": [{"version": "0", "status": "affected", "lessThan": "2.0.13", "versionType": "semver"}],
        }
    ],
    "active_probe_paths": [
        "/dashboard../data/config.yaml",
        "/dashboard%2e%2e/data/config.yaml",
    ],
    "signature_tokens": [
        "CVE-2026-53519", "Nezha", "nezha", "dashboard", "fallbackToFrontend",
        "config.yaml", "jwt_secret_key", "agent_secret_key", "2.0.13", "path traversal",
    ],
}


class NezhaDashboardPathTraversalJWTAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-066"
    meta_poc_name = "Nezha Dashboard Path Traversal JWT Audit"
    meta_cve_id = "CVE-2026-53519"
    meta_severity = "Critical"
    meta_protocol = "http"
    meta_target_os = ["linux", "all"]
    meta_required_params = ["service_banner"]
    meta_profiles = ["network", "monitoring", "edge"]
    meta_source_url = VULN["source_url"]
    meta_attack_surface = "车联网运维监控/边缘节点"
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

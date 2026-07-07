#!/usr/bin/env python3
"""Safe exposure audit for Valkey malformed RESP pre-auth DoS risk."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": "POC-LAB-002",
    "cve": "CVE-2026-27623",
    "year": 2026,
    "domain": "车联网后端/边缘缓存",
    "vendor_product": "Valkey",
    "component": "RESP parser / networking.c",
    "type": "预认证DoS",
    "summary": "Valkey 9.0.0-9.0.2 在处理畸形 RESP pipeline 请求时存在状态机缺陷，可导致预认证服务崩溃；车联网后端缓存、边缘网关与研发台架需排查。",
    "source_description": "poc-lab documents a pre-authentication denial of service caused by malformed RESP input such as an empty multibulk followed by inline command data.",
    "poc_status": "poc-lab公开复现；本插件仅做安全暴露审计",
    "research_value": "Valkey/Redis 兼容组件常见于车联网数据链路与边缘缓存，预认证 DoS 会影响服务可用性。",
    "source_url": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-27623%20Pre-Authentication%20DOS%20from%20malformed%20RESP%20request",
    "references": [
        "https://github.com/Unclecheng-li/poc-lab",
        "https://github.com/valkey-io/valkey/security/advisories/GHSA-93p9-5vc7-8wgr",
        "https://github.com/valkey-io/valkey/commit/2c311dd7173ffc715a3d61266fdede6096a097de",
    ],
    "affected": [
        {
            "vendor": "Valkey",
            "product": "Valkey",
            "versions": [
                {"version": "9.0.0", "status": "affected", "lessThan": "9.0.3", "versionType": "semver"}
            ],
        }
    ],
    "signature_tokens": [
        "CVE-2026-27623", "Valkey", "RESP", "networking.c", "processInputBuffer",
        "parseMultibulk", "pre-auth", "9.0.0", "9.0.1", "9.0.2", "9.0.3",
    ],
}


class ValkeyRESPPreAuthDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-063"
    meta_poc_name = "Valkey RESP Pre-Auth DoS Audit"
    meta_cve_id = "CVE-2026-27623"
    meta_severity = "High"
    meta_protocol = "redis"
    meta_target_os = ["linux", "qnx", "all"]
    meta_required_params = ["service_banner"]
    meta_profiles = ["network", "backend", "edge"]
    meta_source_url = VULN["source_url"]
    meta_attack_surface = "车联网后端/边缘缓存"
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

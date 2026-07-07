#!/usr/bin/env python3
"""Safe exposure audit for NGINX rewrite-module heap overflow risk."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": "POC-LAB-003",
    "cve": "CVE-2026-42945",
    "year": 2026,
    "domain": "车联网网关/OTA/Web入口",
    "vendor_product": "NGINX Open Source / NGINX Plus",
    "component": "ngx_http_rewrite_module",
    "type": "堆缓冲区溢出/DoS或RCE",
    "summary": "NGINX rewrite/set/capture 组合配置在受影响版本中可能触发堆缓冲区溢出；车联网 OTA、API 网关、充电桩网关与边缘代理需排查。",
    "source_description": "poc-lab describes NGINX Rift, a rewrite module heap overflow requiring affected NGINX versions and specific rewrite/set capture-group configuration.",
    "poc_status": "poc-lab公开复现；本插件仅做安全暴露审计",
    "research_value": "NGINX 常作为车联网云端、OTA、边缘代理和设备管理入口，配置型触发条件适合做证据审计。",
    "source_url": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-42945%20NGINX%20Rift",
    "references": ["https://github.com/Unclecheng-li/poc-lab"],
    "affected": [
        {
            "vendor": "NGINX",
            "product": "nginx",
            "versions": [
                {"version": "0.6.27", "status": "affected", "lessThan": "1.30.1", "versionType": "semver"}
            ],
        }
    ],
    "active_probe_paths": [
        "/",
        "/api/autosec_validation",
    ],
    "signature_tokens": [
        "CVE-2026-42945", "NGINX", "nginx", "ngx_http_rewrite_module", "rewrite",
        "set", "capture", "1.30.0", "1.30.1", "1.31.0", "heap buffer overflow",
    ],
}


class NGINXRiftRewriteHeapOverflowAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-064"
    meta_poc_name = "NGINX Rift Rewrite Heap Overflow Audit"
    meta_cve_id = "CVE-2026-42945"
    meta_severity = "High"
    meta_protocol = "http"
    meta_target_os = ["linux", "all"]
    meta_required_params = ["service_banner"]
    meta_profiles = ["network", "gateway", "ota"]
    meta_source_url = VULN["source_url"]
    meta_attack_surface = "车联网网关/OTA/Web入口"
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

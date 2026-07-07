#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 91,
    "cve": "CVE-2023-29406",
    "year": 2023,
    "domain": "车载OS依赖库",
    "vendor_product": "Go stdlib in backend/edge",
    "component": "HTTP/1 client",
    "type": "资源消耗/DoS",
    "summary": "车联网后端/边缘服务依赖Go时需排查的DoS。",
    "source_description": "The HTTP/1 client does not fully validate the contents of the Host header. A maliciously crafted Host header can inject additional headers or entire requests. With fix, the HTTP/1 client now refuses to send requests containing an invalid Request.Host or Request.URL.Host value.",
    "poc_status": "有公开PoC",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-29406",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-29406",
        "https://go.dev/issue/60374",
        "https://go.dev/cl/506996",
        "https://groups.google.com/g/golang-announce/c/2q13H6LEEx0",
        "https://pkg.go.dev/vuln/GO-2023-1878",
        "https://security.netapp.com/advisory/ntap-20230814-0002/",
        "https://security.gentoo.org/glsa/202311-09",
        "https://cveawg.mitre.org/api/cve/CVE-2023-29406"
    ],
    "affected": [
        {
            "vendor": "Go standard library",
            "product": "net/http",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "1.19.11",
                    "versionType": "semver"
                },
                {
                    "version": "1.20.0-0",
                    "status": "affected",
                    "lessThan": "1.20.6",
                    "versionType": "semver"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-29406",
        "stdlib",
        "backend",
        "edge",
        "HTTP",
        "client",
        "DoS",
        "does",
        "fully",
        "validate",
        "contents",
        "Host",
        "header",
        "maliciously",
        "crafted",
        "inject",
        "additional",
        "headers",
        "entire",
        "requests",
        "refuses",
        "send",
        "containing",
        "invalid",
        "Request.Host",
        "Request.URL.Host",
        "value",
        "Go standard library",
        "net/http"
    ]
}


class Poc56CVE202329406DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-091'
    meta_poc_name = 'CVE-2023-29406 资源消耗/DoS Exposure Audit'
    meta_cve_id = 'CVE-2023-29406'
    meta_severity = 'Medium'
    meta_protocol = 'http'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-29406'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

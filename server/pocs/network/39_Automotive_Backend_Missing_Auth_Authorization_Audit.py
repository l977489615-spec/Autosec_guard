#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 45,
    "cve": "CVE-2024-6347",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Automotive backend/charger component",
    "component": "关键功能接口",
    "type": "缺少认证/授权不当",
    "summary": "关键功能缺少认证并存在授权问题。",
    "source_description": "*  Unprotected privileged mode access through UDS session in the Blind Spot Detection Sensor ECU firmware in Nissan Altima (2022) allows attackers to trigger denial-of-service (DoS) by unauthorized access to the ECU's programming session.\n  *  No preconditions implemented for ECU management functionality through UDS session in the Blind Spot Detection Sensor ECU in Nissan Altima (2022) allows attackers to disrupt normal ECU operations by triggering a control command without authentication.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6347",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6347",
        "https://asrg.io/security-advisories/CVE-2024-6347",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6347"
    ],
    "affected": [
        {
            "vendor": "Nissan",
            "product": "Altima",
            "versions": [
                {
                    "version": "Altima 2022",
                    "status": "unknown"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-6347",
        "Automotive",
        "backend",
        "charger",
        "component",
        "Unprotected",
        "privileged",
        "mode",
        "access",
        "session",
        "Blind",
        "Spot",
        "Detection",
        "Sensor",
        "firmware",
        "Nissan",
        "Altima",
        "attackers",
        "trigger",
        "denial-of-service",
        "unauthorized",
        "programming",
        "preconditions",
        "implemented",
        "management",
        "functionality"
    ]
}


class Poc39CVE20246347ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-045'
    meta_poc_name = 'CVE-2024-6347 缺少认证/授权不当 Exposure Audit'
    meta_cve_id = 'CVE-2024-6347'
    meta_severity = 'High'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-6347'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

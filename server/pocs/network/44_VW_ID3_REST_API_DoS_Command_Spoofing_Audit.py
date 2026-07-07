#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 51,
    "cve": "CVE-2023-6073",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Volkswagen ID.3 / ICAS3 IVI ECU",
    "component": "REST API",
    "type": "DoS/命令伪造",
    "summary": "可通过REST API使ICAS3 IVI ECU崩溃并伪造音量设置命令。",
    "source_description": "Attacker can perform a Denial of Service attack to crash the ICAS 3 IVI ECU in a Volkswagen ID.3 (and other vehicles of the VW Group with the same hardware) and spoof volume setting commands to irreversibly turn on audio volume to maximum via REST API calls.\n",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-6073",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-6073",
        "https://asrg.io/cve-2023-6073-dos-and-control-of-volume-settings-for-vw-id-3-icas3-ivi-ecu/",
        "https://cveawg.mitre.org/api/cve/CVE-2023-6073"
    ],
    "affected": [
        {
            "vendor": "Volkswagen",
            "product": "ID.3",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "3.2",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-6073",
        "Volkswagen",
        "ID.3",
        "ICAS3",
        "IVI",
        "ECU",
        "REST",
        "API",
        "DoS",
        "perform",
        "Denial",
        "Service",
        "attack",
        "crash",
        "ICAS",
        "other",
        "Group",
        "same",
        "hardware",
        "spoof",
        "volume",
        "setting",
        "commands",
        "irreversibly",
        "turn",
        "audio",
        "maximum",
        "calls"
    ]
}


class Poc44CVE20236073DoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-051'
    meta_poc_name = 'CVE-2023-6073 DoS/命令伪造 Exposure Audit'
    meta_cve_id = 'CVE-2023-6073'
    meta_severity = 'Medium'
    meta_protocol = 'ocpp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-6073'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

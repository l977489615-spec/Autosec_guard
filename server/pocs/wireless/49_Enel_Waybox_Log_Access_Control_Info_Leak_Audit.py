#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 58,
    "cve": "CVE-2023-29114",
    "year": 2023,
    "domain": "IVI/云端/EVSE/OS",
    "vendor_product": "Enel X Waybox EV charger",
    "component": "web management logs",
    "type": "访问控制不足/敏感信息泄露",
    "summary": "Web管理应用日志可被未授权访问，泄露Wi-Fi/APN/IPSEC凭据。",
    "source_description": "System logs could be accessed through web management application due to a lack of access control.\n\n\nAn attacker can obtain the following sensitive information:\n\n•     Wi-Fi access point credentials to which the EV charger can connect.\n\n•     APN web address and credentials.\n\n•     IPSEC credentials.\n\n•     Web interface access credentials for user and admin accounts.\n\n•     JuiceBox system components (software installed, model, firmware version, etc.).\n\n•     C2G configuration details.\n\n•     Internal IP addresses.\n\n•     OTA firmware update configurations (DNS servers).\n\nAll the credentials are stored in logs in an unencrypted plaintext format.",
    "poc_status": "公开公告；大多未见一步式PoC",
    "research_value": "作为近两年前后演进基线，对比2024-2026风险变化。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-29114",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-29114",
        "https://support-emobility.enelx.com/content/dam/enelxmobility/italia/documenti/manuali-schede-tecniche/Waybox-3-Security-Bulletin-06-2024-V1.pdf",
        "https://cveawg.mitre.org/api/cve/CVE-2023-29114"
    ],
    "affected": [
        {
            "vendor": "Enel X",
            "product": "JuiceBox Pro 3.0 22kW Cellular",
            "versions": [
                {
                    "version": "0",
                    "status": "affected",
                    "lessThan": "2.1.1.0_JB3VU096A",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2023-29114",
        "Enel",
        "Waybox",
        "charger",
        "web",
        "management",
        "logs",
        "System",
        "could",
        "accessed",
        "application",
        "lack",
        "access",
        "control",
        "obtain",
        "following",
        "sensitive",
        "information",
        "Wi-Fi",
        "point",
        "credentials",
        "which",
        "connect",
        "address",
        "IPSEC",
        "interface",
        "user",
        "Enel X",
        "JuiceBox Pro 3.0 22kW Cellular"
    ]
}


class Poc49CVE202329114AccessControlAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-058'
    meta_poc_name = 'CVE-2023-29114 访问控制不足/敏感信息泄露 Exposure Audit'
    meta_cve_id = 'CVE-2023-29114'
    meta_severity = 'High'
    meta_protocol = 'wifi'
    meta_target_os = ['all']
    meta_required_params = ['wireless_scan_text']
    meta_profiles = ['wifi']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2023-29114'
    meta_attack_surface = '无线/外设接口'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

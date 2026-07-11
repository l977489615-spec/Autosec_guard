#!/usr/bin/env python3
"""Active validation PoC for connected-vehicle vulnerability scanning."""
from __future__ import annotations

import socket
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin
from probe_utils import (
    tls_get_server_info, detect_openssl_version,
    openssl_version_affected, detection_confidence,
    score_probe_result, service_open, HTTPProbe,
)


VULN = {
    "id": 90,
    "cve": "CVE-2022-37434",
    "year": 2022,
    "domain": "车载OS依赖库",
    "vendor_product": "zlib/libpng stacks",
    "component": "inflate",
    "type": "整数溢出/内存破坏",
    "summary": "常见压缩库漏洞，车机媒体/OTA包解析可能间接受影响。",
    "source_description": "zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference).",
    "poc_status": "有公开PoC/检测脚本",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-37434",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-37434",
        "https://github.com/ivd38/zlib_overflow",
        "https://github.com/madler/zlib/commit/eff308af425b67093bab25f80f1ae950166bece1",
        "https://github.com/madler/zlib/blob/21767c654d31d2dccdde4330529775c6c5fd5389/zlib.h#L1062-L1063",
        "https://github.com/nodejs/node/blob/75b68c6e4db515f76df73af476eccf382bbcb00a/deps/zlib/inflate.c#L762-L764",
        "http://www.openwall.com/lists/oss-security/2022/08/05/2",
        "https://github.com/curl/curl/issues/9271",
        "http://www.openwall.com/lists/oss-security/2022/08/09/1",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YRQAI7H4M4RQZ2IWZUEEXECBE5D56BH2/",
        "https://www.debian.org/security/2022/dsa-5218",
        "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NMBOJ77A7T7PQCARMDUK75TE6LLESZ3O/",
        "https://cveawg.mitre.org/api/cve/CVE-2022-37434"
    ],
    "affected": [
        {
            "vendor": "zlib",
            "product": "zlib",
            "versions": [
                {"version": "1.2.11", "status": "affected", "lessThan": "1.2.12", "versionType": "semver"},
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2022-37434",
        "zlib",
        "libpng",
        "stacks",
        "inflate",
        "heap-based",
        "buffer",
        "over-read",
        "overflow",
        "inflate.c",
        "large",
        "gzip",
        "header",
        "extra",
        "field",
        "NOTE",
        "only",
        "applications",
        "call",
        "inflateGetHeader",
        "Some",
        "common",
        "bundle",
        "source",
        "code",
        "unable"
    ]
}


def _probe_deflate_compression(host: str, port: int) -> dict:
    """Check if server advertises gzip/deflate and probe zlib version from headers."""
    result = {}
    try:
        use_tls = (port == 443)
        probe = HTTPProbe(host, port, tls=use_tls, timeout=6)
        r = probe.get("/", extra_headers={"Accept-Encoding": "gzip, deflate"})
        result["http_status"] = r.get("status")
        hdrs = r.get("headers", {})
        result["content_encoding"] = hdrs.get("Content-Encoding", "")
        result["server_header"] = hdrs.get("Server", "")
        result["vary_header"] = hdrs.get("Vary", "")
        # Some servers expose zlib version in X- headers or server string
        import re
        server = hdrs.get("Server", "")
        m = re.search(r"zlib/(\d+\.\d+\.\d+)", server, re.IGNORECASE)
        if m:
            result["zlib_version_from_header"] = m.group(1)
    except Exception as exc:
        result["probe_error"] = str(exc)
    return result


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 80))
    cve = "CVE-2022-37434"

    evidence = {
        "cve": cve,
        "target": f"{target_ip}:{port}",
        "technique": "TLS fingerprinting + HTTP gzip/deflate probe + zlib version detection",
        "reference": "https://github.com/ivd38/zlib_overflow",
    }

    if not service_open(target_ip, port):
        evidence["service_open"] = False
        return {
            "vulnerable": None,
            "evidence": evidence,
            "detection_confidence": detection_confidence("E", evidence, "no_service"),
            "requires_manual_review": True,
        }
    evidence["service_open"] = True

    # Step 1: TLS fingerprinting (if HTTPS port)
    if port == 443 or port == 8443:
        tls_info = tls_get_server_info(target_ip, port)
        evidence.update({k: v for k, v in tls_info.items() if v})

    # Step 2: HTTP deflate/gzip probe to check zlib exposure
    deflate_info = _probe_deflate_compression(target_ip, port)
    evidence.update({k: v for k, v in deflate_info.items() if v})

    # Step 3: Check if zlib version is detectable from headers
    detected_version = deflate_info.get("zlib_version_from_header")
    evidence["detected_zlib_version"] = detected_version

    # Step 4: Version comparison using probe_utils
    if detected_version:
        affected = openssl_version_affected(detected_version, cve)
        evidence["version_in_affected_range"] = affected
        evidence["detection_level"] = "C"

        if affected is True:
            vulnerable = True
            conf = detection_confidence("C", evidence, "tls_fingerprint+version_range")
        elif affected is False:
            vulnerable = False
            conf = detection_confidence("C", evidence, "tls_fingerprint+version_range")
        else:
            vulnerable = None
            conf = detection_confidence("E", evidence, "tls_fingerprint_only")
    else:
        # zlib version not visible from network - requires manual check
        evidence["version_detection"] = "failed - zlib version not visible in HTTP headers"
        evidence["detail"] = (
            f"zlib version not detectable from HTTP headers. "
            f"Server: {deflate_info.get('server_header', 'unknown')}. "
            f"Content-Encoding: {deflate_info.get('content_encoding', 'none')}. "
            f"Manual check required: python3 -c 'import zlib; print(zlib.ZLIB_VERSION)'"
        )
        vulnerable = None
        conf = detection_confidence("E", evidence, "http_probe_only")

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "detection_confidence": conf,
        "requires_manual_review": vulnerable is None,
    }


class Poc55CVE202237434ExposureAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-055"
    meta_poc_name = 'CVE-2022-37434 内存破坏 Active Validation'
    meta_cve_id = 'CVE-2022-37434'
    meta_severity = 'High'
    meta_protocol = 'https'
    meta_target_os = ['linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2022-37434'
    meta_references       = ['https://nvd.nist.gov/vuln/detail/CVE-2022-37434']
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "55_Zlib_Inflate_Integer_Overflow_Audit") if "VULN" in dir() else "55_Zlib_Inflate_Integer_Overflow_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = Poc55CVE202237434ExposureAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

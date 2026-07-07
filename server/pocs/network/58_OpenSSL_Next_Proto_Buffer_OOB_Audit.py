#!/usr/bin/env python3
"""Safe CVE exposure audit PoC for connected-vehicle vulnerability intelligence."""
from __future__ import annotations

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin


VULN = {
    "id": 96,
    "cve": "CVE-2024-5535",
    "year": 2024,
    "domain": "车载OS/QNX依赖库",
    "vendor_product": "OpenSSL on QNX",
    "component": "SSL_select_next_proto",
    "type": "缓冲区越界",
    "summary": "OpenSSL协议选择相关内存安全问题，需排查车机依赖。",
    "source_description": "Issue summary: Calling the OpenSSL API function SSL_select_next_proto with an\nempty supported client protocols buffer may cause a crash or memory contents to\nbe sent to the peer.\n\nImpact summary: A buffer overread can have a range of potential consequences\nsuch as unexpected application beahviour or a crash. In particular this issue\ncould result in up to 255 bytes of arbitrary private data from memory being sent\nto the peer leading to a loss of confidentiality. However, only applications\nthat directly call the SSL_select_next_proto function with a 0 length list of\nsupported client protocols are affected by this issue. This would normally never\nbe a valid scenario and is typically not under attacker control but may occur by\naccident in the case of a configuration or programming error in the calling\napplication.\n\nThe OpenSSL API function SSL_select_next_proto is typically used by TLS\napplications that support ALPN (Application Layer Protocol Negotiation) or NPN\n(Next Protocol Negotiation). NPN is older, was never standardised and\nis deprecated in favour of ALPN. We believe that ALPN is significantly more\nwidely deployed than NPN. The SSL_select_next_proto function accepts a list of\nprotocols from the server and a list of protocols from the client and returns\nthe first protocol that appears in the server list that also appears in the\nclient list. In the case of no overlap between the two lists it returns the\nfirst item in the client list. In either case it will signal whether an overlap\nbetween the two lists was found. In the case where SSL_select_next_proto is\ncalled with a zero length client list it fails to notice this condition and\nreturns the memory immediately following the client list pointer (and reports\nthat there was no overlap in the lists).\n\nThis function is typically called from a server side application callback for\nALPN or a client side application callback for NPN. In the case of ALPN the list\nof protocols supplied by the client is guaranteed by libssl to never be zero in\nlength. The list of server protocols comes from the application and should never\nnormally be expected to be of zero length. In this case if the\nSSL_select_next_proto function has been called as expected (with the list\nsupplied by the client passed in the client/client_len parameters), then the\napplication will not be vulnerable to this issue. If the application has\naccidentally been configured with a zero length server list, and has\naccidentally passed that zero length server list in the client/client_len\nparameters, and has additionally failed to correctly handle a \"no overlap\"\nresponse (which would normally result in a handshake failure in ALPN) then it\nwill be vulnerable to this problem.\n\nIn the case of NPN, the protocol permits the client to opportunistically select\na protocol when there is no overlap. OpenSSL returns the first client protocol\nin the no overlap case in support of this. The list of client protocols comes\nfrom the application and should never normally be expected to be of zero length.\nHowever if the SSL_select_next_proto function is accidentally called with a\nclient_len of 0 then an invalid memory pointer will be returned instead. If the\napplication uses this output as the opportunistic protocol then the loss of\nconfidentiality will occur.\n\nThis issue has been assessed as Low severity because applications are most\nlikely to be vulnerable if they are using NPN instead of ALPN - but NPN is not\nwidely used. It also requires an application configuration or programming error.\nFinally, this issue would not typically be under attacker control making active\nexploitation unlikely.\n\nThe FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.\n\nDue to the low severity of this issue we are not issuing new releases of\nOpenSSL at this time. The fix will be included in the next releases when they\nbecome available.",
    "poc_status": "有公开公告",
    "research_value": "作为智能网联汽车常见基础组件/无线协议/车载互联依赖的关联漏洞纳入。",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-5535",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-5535",
        "https://www.openssl.org/news/secadv/20240627.txt",
        "https://github.com/openssl/openssl/commit/e86ac436f0bd54d4517745483e2315650fae7b2c",
        "https://github.com/openssl/openssl/commit/99fb785a5f85315b95288921a321a935ea29a51e",
        "https://github.com/openssl/openssl/commit/4ada436a1946cbb24db5ab4ca082b69c1bc10f37",
        "https://github.com/openssl/openssl/commit/cf6f91f6121f4db167405db2f0de410a456f260c",
        "https://github.openssl.org/openssl/extended-releases/commit/b78ec0824da857223486660177d3b1f255c65d87",
        "https://github.openssl.org/openssl/extended-releases/commit/9947251413065a05189a63c9b7a6c1d4e224c21c",
        "https://cveawg.mitre.org/api/cve/CVE-2024-5535"
    ],
    "affected": [
        {
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "versions": [
                {
                    "version": "3.3.0",
                    "status": "affected",
                    "lessThan": "3.3.2",
                    "versionType": "semver"
                },
                {
                    "version": "3.2.0",
                    "status": "affected",
                    "lessThan": "3.2.3",
                    "versionType": "semver"
                },
                {
                    "version": "3.1.0",
                    "status": "affected",
                    "lessThan": "3.1.7",
                    "versionType": "semver"
                },
                {
                    "version": "3.0.0",
                    "status": "affected",
                    "lessThan": "3.0.15",
                    "versionType": "semver"
                },
                {
                    "version": "1.1.1",
                    "status": "affected",
                    "lessThan": "1.1.1za",
                    "versionType": "custom"
                },
                {
                    "version": "1.0.2",
                    "status": "affected",
                    "lessThan": "1.0.2zk",
                    "versionType": "custom"
                }
            ]
        }
    ],
    "signature_tokens": [
        "CVE-2024-5535",
        "OpenSSL",
        "QNX",
        "SSL_select_next_proto",
        "Issue",
        "summary",
        "Calling",
        "function",
        "empty",
        "supported",
        "client",
        "protocols",
        "buffer",
        "cause",
        "crash",
        "memory",
        "contents",
        "sent",
        "peer",
        "Impact",
        "overread",
        "have",
        "range",
        "potential",
        "consequences",
        "such",
        "unexpected",
        "application",
        "beahviour"
    ]
}


class Poc58CVE20245535OutOfBoundsAuditPlugin(IVIVulnerabilityPlugin):
    meta_display_id = 'XLSX-096'
    meta_poc_name = 'CVE-2024-5535 缓冲区越界 Exposure Audit'
    meta_cve_id = 'CVE-2024-5535'
    meta_severity = 'Medium'
    meta_protocol = 'tls'
    meta_target_os = ['qnx', 'linux']
    meta_required_params = ['tls_scan_text']
    meta_profiles = ['network']
    meta_source_url = 'https://nvd.nist.gov/vuln/detail/CVE-2024-5535'
    meta_attack_surface = '网络服务'
    is_disruptive = False
    meta_destructive_level = "Safe"

    def check_prerequisites(self):
        return True

    def exploit(self):
        return run_active_validation(self, VULN)

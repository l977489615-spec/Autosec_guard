"""Evidence-based advisory PoC helpers.

The generated CVE plugins in this repository are intentionally safe probes:
they do not send exploit payloads. They validate exposure by correlating CVE
metadata, affected-product records, software inventory, SBOM/configuration
evidence, service banners, logs, and optional reachability checks.
"""
from __future__ import annotations

import json
import os
import re
import socket
from typing import Any, Iterable


TEXT_KEYS = (
    "software_inventory_text",
    "component_inventory_text",
    "service_banner",
    "firmware_version",
    "sbom_text",
    "config_text",
    "log_text",
    "wireless_scan_text",
    "can_log_text",
    "uds_log_text",
    "http_response_text",
    "tls_scan_text",
    "ota_config_text",
    "system_property_text",
)

JSON_KEYS = (
    "software_inventory_json",
    "component_inventory_json",
    "sbom_json",
    "service_inventory_json",
)

FIXTURE_KEYS = (
    "software_inventory_fixture",
    "component_inventory_fixture",
    "sbom_fixture",
    "config_fixture",
    "log_fixture",
    "wireless_scan_fixture",
    "can_log_fixture",
    "uds_log_fixture",
    "tls_scan_fixture",
    "ota_config_fixture",
)

WEAK_CONFIG_PATTERNS = {
    "certificate_validation": [
        r"verify(?:_peer|peer|_server|server)?\\s*[:=]\\s*(?:false|0|off|disabled)",
        r"check(?:_hostname|hostname)\\s*[:=]\\s*(?:false|0|off|disabled)",
        r"trust(?:_all|allcerts| all certificates)",
        r"allow(?:_self_signed| self-signed)",
        r"ssl_verify\\s*[:=]\\s*(?:false|0|off)",
    ],
    "signature_verification": [
        r"signature(?:_check|check| verification)?\\s*[:=]\\s*(?:false|0|off|disabled)",
        r"allow(?:_unsigned| unsigned)",
        r"module_sig(?:_enforce)?\\s*[:=]\\s*(?:0|false|disabled)",
    ],
    "authentication": [
        r"auth(?:entication)?\\s*[:=]\\s*(?:none|false|0|disabled|off)",
        r"anonymous\\s*[:=]\\s*(?:true|1|enabled)",
        r"no authentication",
        r"unauthenticated",
    ],
    "replay": [
        r"rolling(?:_| )?code\\s*[:=]\\s*(?:false|0|disabled)",
        r"fixed(?:_| )?(?:code|challenge|token)",
        r"nonce\\s*[:=]\\s*(?:static|fixed|0)",
    ],
    "weak_random": [
        r"srand\\s*\\(\\s*(?:0|1|time\\(NULL\\))\\s*\\)",
        r"random_seed\\s*[:=]\\s*(?:0|1|fixed|static)",
        r"predictable\\s+(?:random|challenge|nonce)",
    ],
    "debug_exposure": [
        r"debug\\s*[:=]\\s*(?:true|1|enabled)",
        r"developer(?:_| )?mode\\s*[:=]\\s*(?:true|1|enabled)",
        r"shell\\s*[:=]\\s*(?:enabled|root)",
    ],
}


def run_advisory_audit(plugin: Any, vuln: dict[str, Any]) -> dict[str, Any]:
    evidence_items = collect_evidence(plugin.params or {})
    haystack = "\n".join(evidence_items)
    haystack_l = haystack.lower()

    token_hits = _token_hits(vuln.get("signature_tokens", []), haystack_l)
    product_hits = _product_hits(vuln.get("affected", []), haystack_l)
    config_hits = _config_hits(vuln, haystack)
    version_hits = _version_hits(vuln.get("affected", []), haystack_l)
    explicit_cve = str(vuln.get("cve", "")).lower() in haystack_l

    score = 0
    score += 5 if explicit_cve else 0
    score += min(len(product_hits), 3) * 2
    score += min(len(token_hits), 5)
    score += min(len(config_hits), 3) * 2
    score += min(len(version_hits), 3) * 2

    # A PoC should not report vulnerable just because the file exists. Require
    # either an explicit CVE mention, an affected product plus a second signal,
    # or multiple independent weak-configuration/version indicators.
    vulnerable = bool(
        explicit_cve
        or (product_hits and (config_hits or version_hits or len(token_hits) >= 2))
        or (len(config_hits) >= 2 and token_hits)
        or (len(version_hits) >= 2 and token_hits)
    )

    if not evidence_items and getattr(plugin, "target_ip", None):
        evidence_items.append(_safe_reachability_note(plugin))

    result_evidence = {
        "cve": vuln.get("cve"),
        "source_url": vuln.get("source_url"),
        "references": vuln.get("references", [])[:8],
        "vendor_product": vuln.get("vendor_product"),
        "component": vuln.get("component"),
        "vulnerability_type": vuln.get("type"),
        "matched_signature_tokens": token_hits,
        "matched_affected_products": product_hits,
        "matched_weak_config_patterns": config_hits,
        "matched_version_evidence": version_hits,
        "explicit_cve_observed": explicit_cve,
        "confidence_score": score,
        "assessment_basis": (
            "Passive exposure evidence phase. Active probes, trigger payloads, "
            "manual confirmation, and target-side phenomena are recorded separately "
            "by active_validation_core when enabled."
        ),
        "evidence_items": len(evidence_items),
        "summary": vuln.get("summary"),
        "source_description": vuln.get("source_description") or vuln.get("summary"),
    }
    return {
        "vulnerable": vulnerable,
        "cve_id": vuln.get("cve", ""),
        "description": vuln.get("summary", ""),
        "evidence": json.dumps(result_evidence, ensure_ascii=False),
    }


def collect_evidence(params: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in TEXT_KEYS:
        value = params.get(key) or os.environ.get(f"AUTOSEC_{key.upper()}")
        if value not in (None, ""):
            values.append(str(value))
    for key in JSON_KEYS:
        value = params.get(key) or os.environ.get(f"AUTOSEC_{key.upper()}")
        if value not in (None, ""):
            values.append(_json_to_text(value))
    for key in FIXTURE_KEYS:
        fixture = params.get(key) or os.environ.get(f"AUTOSEC_{key.upper()}")
        if fixture and os.path.isfile(str(fixture)):
            values.append(open(str(fixture), "r", encoding="utf-8", errors="ignore").read())
    return values


def _json_to_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    try:
        parsed = json.loads(str(value))
        return json.dumps(parsed, ensure_ascii=False)
    except Exception:
        return str(value)


def _token_hits(tokens: Iterable[str], haystack_l: str) -> list[str]:
    hits = []
    for token in tokens:
        token = str(token or "").strip()
        if len(token) < 3:
            continue
        if token.lower() in haystack_l and token not in hits:
            hits.append(token)
    return hits[:20]


def _product_hits(affected: list[dict[str, Any]], haystack_l: str) -> list[str]:
    hits = []
    for item in affected or []:
        vendor = str(item.get("vendor") or "").strip()
        product = str(item.get("product") or "").strip()
        label = " ".join(part for part in (vendor, product) if part).strip()
        if not label:
            continue
        vendor_hit = vendor and vendor.lower() in haystack_l
        product_hit = product and product.lower() in haystack_l
        if product_hit or (vendor_hit and len(product) < 4):
            hits.append(label)
    return hits[:12]


def _config_hits(vuln: dict[str, Any], haystack: str) -> list[str]:
    text = " ".join(
        str(vuln.get(key, ""))
        for key in ("type", "summary", "source_description", "component")
    ).lower()
    families = []
    if any(x in text for x in ("cert", "certificate", "tls", "ssl", "root certificate")):
        families.append("certificate_validation")
    if any(x in text for x in ("signature", "unsigned", "module")):
        families.append("signature_verification")
    if any(x in text for x in ("auth", "credential", "login", "permission", "access control")):
        families.append("authentication")
    if any(x in text for x in ("replay", "rolling", "keyless")):
        families.append("replay")
    if any(x in text for x in ("random", "entropy", "nonce", "predictable")):
        families.append("weak_random")
    if any(x in text for x in ("debug", "developer", "shell")):
        families.append("debug_exposure")

    hits = []
    for family in families:
        for pattern in WEAK_CONFIG_PATTERNS.get(family, []):
            if re.search(pattern, haystack, re.IGNORECASE):
                hits.append(f"{family}:{pattern}")
                break
    return hits


def _version_hits(affected: list[dict[str, Any]], haystack_l: str) -> list[str]:
    hits = []
    for item in affected or []:
        product = str(item.get("product") or "").strip()
        for version in item.get("versions") or []:
            raw = str(version.get("version") or "").strip()
            status = str(version.get("status") or "").strip()
            upper = str(version.get("lessThanOrEqual") or "").strip()
            lower = str(version.get("lessThan") or "").strip()
            if raw and raw not in {"0", "*", "-", "n/a"} and raw.lower() in haystack_l:
                hits.append(f"{product} version {raw} status={status}")
            if upper and upper.lower() in haystack_l:
                hits.append(f"{product} <= {upper}")
            if lower and lower.lower() in haystack_l:
                hits.append(f"{product} < {lower}")
    return hits[:12]


def _safe_reachability_note(plugin: Any) -> str:
    port = plugin.params.get("target_port") or getattr(plugin, "target_port", None)
    if not port:
        return (
            f"target_ip supplied ({plugin.target_ip}), but no target_port or "
            "evidence fixture was provided; exposure cannot be confirmed safely"
        )
    try:
        with socket.create_connection((plugin.target_ip, int(port)), timeout=float(plugin.params.get("timeout", 2))):
            return (
                f"TCP service reachable at {plugin.target_ip}:{port}; provide "
                "banner/SBOM/config evidence to confirm CVE-specific exposure"
            )
    except OSError as exc:
        return f"TCP service not reachable at {plugin.target_ip}:{port}: {exc}"

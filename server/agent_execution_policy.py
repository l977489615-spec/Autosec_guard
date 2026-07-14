from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Iterable, Tuple


RISK_LEVEL_ORDER = {
    "SAFE": 0,
    "PROBE": 1,
    "RESTART": 2,
    "DATALOSS": 3,
    "BRICK": 4,
}

EXECUTION_MODE_DEFAULTS = {
    "SAFE_ONLY": "PROBE",
    "PROGRESSIVE_AUTO": "RESTART",
    "FULL_AUTO_LAB": "DATALOSS",
}

DESTRUCTIVE_LEVEL_TO_RISK = {
    "safe": "SAFE",
    "probe": "PROBE",
    "restart": "RESTART",
    "disruptive": "RESTART",
    "dataloss": "DATALOSS",
    "brick": "BRICK",
}

DESTRUCTIVE_POLICIES = {"ALLOW_ALL", "CONFIRM_EACH", "DENY_ALL"}


def normalize_destructive_policy(policy: str | None) -> str:
    """Normalize the operator's decision policy independently of the risk ceiling."""
    raw = str(policy or "").strip().lower().replace("-", "_")
    aliases = {
        "allow_all": "ALLOW_ALL",
        "all_allow": "ALLOW_ALL",
        "allow": "ALLOW_ALL",
        "全部允许": "ALLOW_ALL",
        "confirm_each": "CONFIRM_EACH",
        "manual_confirm": "CONFIRM_EACH",
        "confirm": "CONFIRM_EACH",
        "人工确认": "CONFIRM_EACH",
        "deny_all": "DENY_ALL",
        "all_deny": "DENY_ALL",
        "deny": "DENY_ALL",
        "全部拒绝": "DENY_ALL",
    }
    return aliases.get(raw, "CONFIRM_EACH")


def normalize_execution_mode(mode: str | None, approve_high_risk_batch: bool = False) -> str:
    raw = str(mode or "").strip().lower()
    aliases = {
        "safe_only": "SAFE_ONLY",
        "safe-only": "SAFE_ONLY",
        "safe": "SAFE_ONLY",
        "conservative": "SAFE_ONLY",
        "progressive_auto": "PROGRESSIVE_AUTO",
        "progressive-auto": "PROGRESSIVE_AUTO",
        "progressive": "PROGRESSIVE_AUTO",
        "auto": "PROGRESSIVE_AUTO",
        "full_auto_lab": "FULL_AUTO_LAB",
        "full-auto-lab": "FULL_AUTO_LAB",
        "lab": "FULL_AUTO_LAB",
        "lab_auto": "FULL_AUTO_LAB",
    }
    if raw in aliases:
        return aliases[raw]
    if approve_high_risk_batch:
        return "PROGRESSIVE_AUTO"
    return "SAFE_ONLY"


def normalize_risk_level(level: str | None) -> str:
    raw = str(level or "").strip().upper()
    if raw in RISK_LEVEL_ORDER:
        return raw
    return "SAFE"


def default_risk_ceiling(execution_mode: str | None) -> str:
    mode = normalize_execution_mode(execution_mode)
    return EXECUTION_MODE_DEFAULTS.get(mode, "PROBE")


def risk_level_from_profile(profile: Dict[str, Any] | None) -> str:
    profile = profile or {}
    destructive = str(profile.get("destructive_level") or profile.get("meta_destructive_level") or "").strip().lower()
    risk = DESTRUCTIVE_LEVEL_TO_RISK.get(destructive)
    if risk:
        return risk
    if bool(profile.get("is_disruptive")):
        return "RESTART"
    return "SAFE"


def risk_level_allows(risk_ceiling: str | None, risk_level: str | None) -> bool:
    ceiling = normalize_risk_level(risk_ceiling or "SAFE")
    level = normalize_risk_level(risk_level)
    return RISK_LEVEL_ORDER[level] <= RISK_LEVEL_ORDER[ceiling]


def should_use_safe_pass(risk_level: str | None) -> bool:
    return normalize_risk_level(risk_level) in {"SAFE", "PROBE"}


def allowed_domains_set(allowed_domains: Iterable[str] | str | None) -> set[str]:
    if allowed_domains is None:
        return set()
    if isinstance(allowed_domains, str):
        items = allowed_domains.split(",")
    else:
        items = list(allowed_domains)
    return {str(item).strip().lower() for item in items if str(item).strip()}


def preflight_profile(
    *,
    profile: Dict[str, Any] | None,
    params: Dict[str, Any] | None,
    domain: str = "",
    target_in_scope: bool = True,
    lab_policy: bool = False,
    allowed_domains: Iterable[str] | str | None = None,
    operator_approved: bool = False,
) -> Dict[str, Any]:
    profile = profile or {}
    params = params or {}
    required = [str(item).strip() for item in (profile.get("required_params") or []) if str(item).strip()]
    missing = [name for name in required if params.get(name) in (None, "", [])]
    allowed = allowed_domains_set(allowed_domains)
    domain_ok = True if not allowed else str(domain or "").strip().lower() in allowed
    preflight_ready = target_in_scope and domain_ok and not missing
    risk_level = risk_level_from_profile(profile)
    requirements = []
    if missing:
        requirements.append(f"missing_required_params={','.join(missing)}")
    if not target_in_scope:
        requirements.append("target_out_of_scope")
    if allowed and not domain_ok:
        requirements.append("domain_not_authorized")
    if (
        normalize_risk_level(risk_level) in {"DATALOSS", "BRICK"}
        and not lab_policy
        and not operator_approved
    ):
        requirements.append("lab_policy_required")
    expected = profile.get("expected_observable") or _default_expected_observable(profile)
    return {
        "risk_level": risk_level,
        "required_params_present": not missing,
        "missing_required_params": missing,
        "target_in_scope": bool(target_in_scope),
        "domain_authorized": bool(domain_ok),
        "allowed_domains": sorted(allowed),
        "preflight_ready": bool(preflight_ready),
        "auto_escalation_requirements": requirements,
        "eligible_for_progressive_auto": bool(preflight_ready and normalize_risk_level(risk_level) == "RESTART"),
        "expected_observable": expected,
    }


def allow_automatic_escalation(
    *,
    execution_mode: str | None,
    risk_level: str | None,
    risk_ceiling: str | None,
    preflight_ready: bool,
    lab_policy: bool = False,
    operator_approved: bool = False,
) -> Tuple[bool, str]:
    mode = normalize_execution_mode(execution_mode)
    level = normalize_risk_level(risk_level)
    ceiling = normalize_risk_level(risk_ceiling or default_risk_ceiling(mode))

    if operator_approved:
        return True, "operator-approved"
    if should_use_safe_pass(level):
        return True, "safe-pass"
    if not risk_level_allows(ceiling, level):
        return False, "risk-ceiling-blocked"
    if level == "BRICK":
        return False, "brick-blocked"
    if level == "DATALOSS" and not (mode == "FULL_AUTO_LAB" and lab_policy):
        return False, "lab-policy-required"
    if mode == "SAFE_ONLY":
        return False, "safe-only-mode"
    if mode == "PROGRESSIVE_AUTO" and level != "RESTART":
        return False, "progressive-mode-restart-only"
    if not preflight_ready:
        return False, "preflight-not-ready"
    return True, "auto-escalation-allowed"


def issue_signed_scope_token(secret_key: str, payload: Dict[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(secret_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    raw = json.dumps({"payload": payload, "sig": sig}, ensure_ascii=False, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def verify_signed_scope_token(
    secret_key: str,
    token: str,
    *,
    ttl_seconds: int,
    expected_pairs: Dict[str, Any] | None = None,
) -> Tuple[bool, Dict[str, Any], str]:
    if not token:
        return False, {}, "missing"
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        parsed = json.loads(raw)
        payload = parsed["payload"]
        sig = parsed["sig"]
    except Exception:
        return False, {}, "decode_failed"
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    expected_sig = hmac.new(secret_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False, {}, "bad_signature"
    issued_at = int(payload.get("issued_at") or 0)
    if issued_at <= 0 or time.time() - issued_at > int(ttl_seconds):
        return False, payload, "expired"
    for key, expected_value in (expected_pairs or {}).items():
        if payload.get(key) != expected_value:
            return False, payload, f"mismatch:{key}"
    return True, payload, "ok"


def _default_expected_observable(profile: Dict[str, Any]) -> str:
    protocol = str(profile.get("protocol") or "").lower()
    risk_level = risk_level_from_profile(profile)
    if protocol in {"http", "https", "tcp", "redis", "airplay", "rtsp"}:
        return "service state change, response anomaly, unauthorized action, or controlled reset"
    if protocol in {"wifi", "bluetooth", "ble"}:
        return "connection drop, association anomaly, pairing state change, or target-side reset"
    if risk_level == "SAFE":
        return "non-destructive verification evidence"
    return "controlled target-side crash, reset, or privileged state transition"

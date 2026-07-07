"""重入风险状态判定与车联网 PoC 安全补证。

当反思（Reflector）因证据不足触发 PoC 重入/补证时，本模块不直接重跑破坏性
PoC，而是：
1) 对重入动作做"二次风险判定"——因为目标状态、失败原因、证据缺口在重入时已发生
   变化，破坏等级需重新计算（compute_reentry_risk_state）；
2) 据风险状态自动生成"安全补证策略"——原样重跑 / 低扰动等效探针替换 / 只读降级 /
   一次性授权令牌受限执行 / 阻断（generate_safe_revalidation_strategy）；
3) 低扰动等效探针通过"降级映射表"（DOWNGRADE_MAP）由破坏性原语查表生成，保证补证
   动作既不扰动车辆状态、又不丢失证据收益。

与 poc_security.should_require_disruptive_approval 的区别：后者是静态的"破坏脚本是否
需审批"判定；本模块是重入场景下的动态风险再判定 + 等效安全替代动作生成。
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# 破坏性原语识别：从 PoC 名称/类别/协议中识别其执行的破坏性动作类型
# ---------------------------------------------------------------------------
_PRIMITIVE_KEYWORDS = {
    "bus_write": ["write", "writedata", "wdbi", "0x2e", "总线写", "写入"],
    "diag_session_switch": ["session", "securityaccess", "0x27", "0x10", "诊断会话", "扩展会话"],
    "injection": ["inject", "spoof", "replay", "forge", "注入", "伪造", "重放"],
    "flooding": ["flood", "dos", "storm", "泛洪", "拒绝服务"],
    "fuzzing": ["fuzz", "模糊测试"],
    "reset": ["reboot", "restart", "reset", "brick", "重启", "复位", "砖化"],
    "wireless_disrupt": ["deauth", "jam", "disassoc", "去认证", "干扰"],
}

# 攻击面 / 协议 → 缺省破坏性原语（关键字未命中时的兜底）
_SURFACE_DEFAULT_PRIMITIVE = {
    "CAN/UDS/OBD": "bus_write",
    "无线/外设接口": "injection",
    "车机APP/应用": "app_destructive",
    "系统配置/本地制品": "app_destructive",
    "固件/USB/OTA": "reset",
}

# ---------------------------------------------------------------------------
# 降级映射表：破坏性原语 → 低扰动等效探针（保证证据收益、不扰动车辆状态）
# 这是"安全补证自动生成"的可实现内核：把"自动生成"落成"查表降级"。
# ---------------------------------------------------------------------------
DOWNGRADE_MAP: Dict[str, Dict[str, str]] = {
    "bus_write": {
        "probe": "uds_did_readonly",
        "mode": "readonly",
        "evidence": "以只读 ReadDataByIdentifier 读取目标 DID 与会话/权限状态，确认可达性与写前提，而不向总线写入",
    },
    "diag_session_switch": {
        "probe": "tester_present_passive",
        "mode": "passive",
        "evidence": "以被动 TesterPresent/会话探测确认诊断可达与安全访问等级，不实际切换会话状态",
    },
    "injection": {
        "probe": "passive_capture",
        "mode": "monitor",
        "evidence": "被动抓包/监听确认报文可见性与字段结构，替代主动注入，不改变目标状态",
    },
    "flooding": {
        "probe": "rate_limited_single_probe",
        "mode": "throttled",
        "evidence": "限速单包探测确认服务存活与响应特征，替代泛洪，不造成总线/链路拥塞",
    },
    "fuzzing": {
        "probe": "boundary_readonly_check",
        "mode": "readonly",
        "evidence": "只读边界值/长度字段检查确认解析路径，替代大流量模糊测试",
    },
    "reset": {
        "probe": "version_banner_read",
        "mode": "readonly",
        "evidence": "只读读取版本/Banner/状态寄存器确认目标存在与版本，替代会触发重启/复位的动作",
    },
    "wireless_disrupt": {
        "probe": "passive_rf_monitor",
        "mode": "monitor",
        "evidence": "被动射频/链路监听确认信道与连接状态，替代去认证/干扰，不中断既有连接",
    },
    "app_destructive": {
        "probe": "readonly_config_inspect",
        "mode": "readonly",
        "evidence": "只读配置检查/ADB 只读查询确认配置项与组件状态，替代破坏性写入/卸载操作",
    },
}

# 破坏等级 → 基础风险分（与 poc_security 的等级口径一致）
_DESTRUCTIVE_BASE = {
    "safe": 0.0, "low": 0.2, "medium": 0.5, "high": 0.8,
    "restart": 0.9, "dataloss": 0.95, "brick": 1.0, "critical": 1.0,
}

# 高破坏原语额外风险增量
_PRIMITIVE_RISK = {
    "bus_write": 0.3, "diag_session_switch": 0.25, "injection": 0.25,
    "flooding": 0.35, "fuzzing": 0.3, "reset": 0.4,
    "wireless_disrupt": 0.3, "app_destructive": 0.2,
}


def identify_destructive_primitive(profile: Dict[str, Any]) -> Optional[str]:
    """从 PoC 元数据识别其破坏性原语类型，识别不到返回 None（视为非破坏性）。"""
    text = " ".join(str(profile.get(k) or "") for k in (
        "poc_name", "display_id", "category", "protocol")).lower()
    for primitive, kws in _PRIMITIVE_KEYWORDS.items():
        if any(kw in text for kw in kws):
            return primitive
    # 关键字未命中：若标记为破坏性，则按攻击面兜底
    destructive = str(profile.get("destructive_level") or "").lower()
    if profile.get("is_disruptive") or destructive in ("medium", "high", "restart", "dataloss", "brick", "critical"):
        return _SURFACE_DEFAULT_PRIMITIVE.get(str(profile.get("attack_surface") or ""), "app_destructive")
    return None


def compute_reentry_risk_state(profile: Dict[str, Any],
                               context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """重入动作的二次风险判定。

    profile: PoC 元数据（destructive_level, is_disruptive, category, protocol, attack_surface, poc_name…）
    context: 重入上下文，可含 target_state、failure_reason、evidence_gap、param_changed、retry_count。
    返回 risk_state：score∈[0,1]、level、primitive 及各因子明细。
    """
    ctx = context or {}
    destructive = str(profile.get("destructive_level") or "safe").lower()
    primitive = identify_destructive_primitive(profile)

    base = _DESTRUCTIVE_BASE.get(destructive, 0.3)
    prim_risk = _PRIMITIVE_RISK.get(primitive, 0.0) if primitive else 0.0

    # 目标当前状态：若上一轮已观测到目标不稳定/高负载，重入风险上调
    target_state = str(ctx.get("target_state") or "").lower()
    state_risk = 0.0
    if any(t in target_state for t in ("unstable", "high_load", "degraded", "异常", "高负载", "不稳定")):
        state_risk = 0.2

    # 执行参数变化：补证时若改写了参数（尤其写入类），风险上调
    param_risk = 0.1 if ctx.get("param_changed") else 0.0

    # 历史失败原因：超时/连接中断类失败再打可能加剧扰动
    failure_reason = str(ctx.get("failure_reason") or "").lower()
    failure_risk = 0.0
    if any(t in failure_reason for t in ("timeout", "reset", "disconnect", "crash", "超时", "中断", "崩溃")):
        failure_risk = 0.15

    # 连续重试次数累积风险
    retry_count = int(ctx.get("retry_count") or 0)
    retry_risk = min(retry_count * 0.1, 0.3)

    # 仅当存在实际破坏性（破坏性原语 / 非安全等级 / 标记干扰）时，上下文因子才足额计入；
    # 否则（纯安全无破坏动作的 PoC）上下文因子大幅衰减，避免把安全侦察误判为高风险。
    destructive_present = (
        primitive is not None
        or destructive not in ("safe", "low")
        or bool(profile.get("is_disruptive"))
    )
    ctx_scale = 1.0 if destructive_present else 0.25
    contextual = (state_risk + param_risk + failure_risk + retry_risk) * ctx_scale

    score = min(base + prim_risk + contextual, 1.0)
    if score >= 0.85:
        level = "critical"
    elif score >= 0.6:
        level = "high"
    elif score >= 0.35:
        level = "medium"
    else:
        level = "low"

    return {
        "score": round(score, 3),
        "level": level,
        "primitive": primitive,
        "destructive_level": destructive,
        "is_disruptive": bool(profile.get("is_disruptive")),
        "factors": {
            "base": base, "primitive": prim_risk, "target_state": state_risk,
            "param_changed": param_risk, "failure_reason": failure_risk, "retry": retry_risk,
        },
        "evidence_type": str(ctx.get("evidence_gap") or profile.get("category") or ""),
    }


@dataclass
class OneTimeAuthToken:
    """一次性授权令牌：绑定目标、PoC、参数、时间窗口与执行次数。"""
    token_id: str
    target: str
    poc_id: str
    params_hash: str
    issued_at: float
    expires_at: float
    max_uses: int = 1
    used: int = 0

    @classmethod
    def issue(cls, target: str, poc_id: str, params: Dict[str, Any],
              ttl_seconds: int = 600, max_uses: int = 1) -> "OneTimeAuthToken":
        now = time.time()
        raw = f"{target}|{poc_id}|{sorted((params or {}).items())}|{now}"
        params_hash = hashlib.sha256(
            str(sorted((params or {}).items())).encode("utf-8")).hexdigest()[:16]
        token_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
        return cls(token_id=token_id, target=target, poc_id=poc_id,
                   params_hash=params_hash, issued_at=now,
                   expires_at=now + ttl_seconds, max_uses=max_uses)

    def validate(self, target: str, poc_id: str, params: Dict[str, Any]) -> bool:
        if time.time() > self.expires_at or self.used >= self.max_uses:
            return False
        if target != self.target or poc_id != self.poc_id:
            return False
        ph = hashlib.sha256(str(sorted((params or {}).items())).encode("utf-8")).hexdigest()[:16]
        return ph == self.params_hash

    def consume(self) -> bool:
        if self.used >= self.max_uses:
            return False
        self.used += 1
        return True


def generate_safe_revalidation_strategy(profile: Dict[str, Any],
                                        risk_state: Dict[str, Any],
                                        context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """据重入风险状态生成安全补证策略。

    策略阶梯：original_rerun → low_disturbance_probe → readonly_downgrade →
    one_time_auth → block。低扰动/只读策略通过 DOWNGRADE_MAP 查表生成等效探针，
    保证证据收益（evidence_preserved=True）。
    """
    ctx = context or {}
    level = risk_state.get("level", "low")
    primitive = risk_state.get("primitive")
    has_explicit_auth = bool(ctx.get("authorized"))
    downgrade = DOWNGRADE_MAP.get(primitive) if primitive else None

    substitute_probe: Optional[Dict[str, str]] = None
    auth_token: Optional[Dict[str, Any]] = None
    evidence_preserved = True

    # 非破坏 / 低风险：原样定向重跑
    if primitive is None or level == "low":
        strategy = "original_rerun"
        rationale = "重入风险低，原 PoC 可定向重跑，无需降级。"

    # 中风险：替换为低扰动等效探针
    elif level == "medium" and downgrade:
        strategy = "low_disturbance_probe"
        substitute_probe = {
            "probe": downgrade["probe"], "mode": downgrade["mode"],
            "replaces": risk_state.get("primitive"), "evidence": downgrade["evidence"],
        }
        rationale = "中风险：以低扰动等效探针替换破坏性动作，保证证据收益且不扰动目标。"

    # 高风险：降级为只读验证
    elif level == "high" and downgrade:
        strategy = "readonly_downgrade"
        substitute_probe = {
            "probe": downgrade["probe"], "mode": "readonly",
            "replaces": risk_state.get("primitive"), "evidence": downgrade["evidence"],
        }
        rationale = "高风险：降级为只读等效验证，仅确认前提与可达性，不执行破坏性动作。"

    # 极高风险：要求一次性授权令牌后受限执行；无授权则阻断
    else:  # critical 或无可用降级
        if has_explicit_auth:
            strategy = "one_time_auth"
            token = OneTimeAuthToken.issue(
                target=str(ctx.get("target") or ""),
                poc_id=str(profile.get("display_id") or profile.get("poc_name") or ""),
                params=ctx.get("params") or {},
                ttl_seconds=int(ctx.get("auth_ttl_seconds") or 600),
            )
            auth_token = asdict(token)
            rationale = "极高风险：绑定一次性授权令牌（限目标/PoC/参数/时间窗/次数）后受限执行。"
        else:
            strategy = "block"
            evidence_preserved = bool(downgrade)
            if downgrade:
                substitute_probe = {
                    "probe": downgrade["probe"], "mode": "readonly",
                    "replaces": risk_state.get("primitive"), "evidence": downgrade["evidence"],
                }
                rationale = "极高风险且未授权：阻断破坏性重跑，建议改用只读等效探针或申请一次性授权。"
            else:
                rationale = "极高风险、无可用等效降级且未授权：阻断本次重入，转人工介入。"

    return {
        "strategy": strategy,
        "substitute_probe": substitute_probe,
        "auth_token": auth_token,
        "evidence_preserved": evidence_preserved,
        "rationale": rationale,
    }


def plan_safe_reentry(profile: Dict[str, Any],
                      context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """单个重入 PoC 的安全补证完整规划：风险再判定 + 策略生成。"""
    risk_state = compute_reentry_risk_state(profile, context)
    strategy = generate_safe_revalidation_strategy(profile, risk_state, context)
    return {
        "poc_id": profile.get("display_id") or profile.get("poc_name") or "",
        "poc_name": profile.get("poc_name") or "",
        "risk_state": risk_state,
        **strategy,
    }


def plan_safe_reentry_batch(profiles: List[Dict[str, Any]],
                            context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """对一批重入目标 PoC 批量生成安全补证策略。"""
    return [plan_safe_reentry(p, context) for p in (profiles or [])]

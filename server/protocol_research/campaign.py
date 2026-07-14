"""Campaign orchestration and Stage-04 active-fuzz gate evaluation."""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .corpus import CorpusManager
from .corpus_resolver import resolve_corpus_for_params
from .corpus_store import default_candidate_poc_dir
from .field_inference import enrich_symbols
from .health_observer import ScriptedHealthObserver, TcpPortHealthObserver
from .message_clustering import cluster_messages
from .minimizer import minimize_candidate
from .models import CorpusDocument, ProtocolModel, ProtocolTestPlan
from .mutators import mutate_seed_sequence
from .poc_depositor import PocDepositor
from .reproducer import reproduce_anomaly
from .seed_scheduler import build_seeds_from_sessions
from .state_machine import infer_state_machine
from .transport import DryRunTransportAdapter, TcpTransportAdapter


@dataclass
class FuzzGateDecision:
    allowed: bool
    reasons: list[str]
    mode: str  # fingerprint | offline_inference | stateful_fuzz

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_active_fuzz_gates(
    *,
    service_covered_by_existing_poc: bool,
    has_valid_seed_corpus: bool,
    execution_mode: str,
    lab_policy: bool,
    active_test_approved: bool,
) -> FuzzGateDecision:
    reasons: list[str] = []
    if service_covered_by_existing_poc:
        reasons.append("service_covered_by_existing_poc")
    if not has_valid_seed_corpus:
        reasons.append("missing_valid_seed_corpus")
    mode = str(execution_mode or "").strip().lower().replace("-", "_")
    if mode != "full_auto_lab":
        reasons.append("execution_mode_not_full_auto_lab")
    if not lab_policy:
        reasons.append("lab_policy_required")
    if not active_test_approved:
        reasons.append("active_test_approval_required")

    if not reasons:
        return FuzzGateDecision(True, ["all_gates_passed"], "stateful_fuzz")
    if has_valid_seed_corpus and not service_covered_by_existing_poc:
        return FuzzGateDecision(False, reasons, "offline_inference")
    return FuzzGateDecision(False, reasons, "fingerprint")


def run_offline_inference(corpus: CorpusDocument) -> ProtocolModel:
    messages = [m for s in corpus.sessions for m in s.messages]
    symbols = enrich_symbols(cluster_messages(messages))
    return infer_state_machine(corpus, symbols)


def run_stateful_fuzz_campaign(
    *,
    corpus: CorpusDocument,
    gates: FuzzGateDecision,
    dry_run: bool = False,
    max_cases: int = 24,
    deposit_dir: str | None = None,
    health: dict[str, Any] | None = None,
    health_fn: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    campaign_id = f"FUZZ-{time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    model = run_offline_inference(corpus)
    seeds = build_seeds_from_sessions(corpus, model)
    feedback: dict[str, Any] = {
        "new_response_types": [],
        "new_transitions": [],
        "effective_mutations": 0,
        "candidate_anomalies": 0,
    }
    result: dict[str, Any] = {
        "campaign_id": campaign_id,
        "gates": gates.to_dict(),
        "model": model.to_dict(),
        "seeds": [s.to_dict() for s in seeds],
        "cases_executed": 0,
        "anomalies": [],
        "manifests": [],
        "feedback": feedback,
        "session_mode": "stateful_tcp",
        "vulnerable": False,
        "note": "",
    }
    if not gates.allowed:
        result["note"] = "active fuzz blocked by gates; offline inference only"
        return result

    host = str(corpus.target.get("ip"))
    port = int(corpus.target.get("port"))
    if dry_run:
        transport: Any = DryRunTransportAdapter(stateful=True)
        observer = ScriptedHealthObserver(baseline_alive=True)
    else:
        transport = TcpTransportAdapter(host, port, max_exchanges=max_cases * 4, stateful=True)
        observer = TcpPortHealthObserver(host, port)
        observer.snapshot(after_mutation=False)

    if deposit_dir is None and not dry_run:
        deposit_dir = str(default_candidate_poc_dir())

    baseline = seeds[0].messages_hex if seeds else []
    anomalies = []
    manifests = []
    cases = 0

    def _make_play(t=transport, obs=observer):
        def _play(msgs: list[str]):
            if hasattr(t, "calls"):
                pass
            results = t.play_sequence(msgs)
            if hasattr(t, "calls"):
                obs.observe_calls(list(t.calls))
            return results
        return _play

    def _make_health(obs=observer, static=health or {}):
        def _health(*, after_mutation: bool = False):
            dynamic = obs.snapshot(after_mutation=after_mutation)
            merged = {**static, **dynamic}
            if health_fn:
                merged.update(health_fn() or {})
            return merged
        return _health

    play = _make_play()
    health_after = _make_health()

    for seed in seeds[:5]:
        for case in mutate_seed_sequence(seed.messages_hex, model.symbols, max_cases=8):
            if cases >= max_cases:
                break
            cases += 1
            anomaly = reproduce_anomaly(
                baseline_messages=baseline or case[:1],
                candidate_messages=case,
                play=play,
                health=lambda ah=health_after: ah(after_mutation=True),
                attempts=3 if not dry_run else 1,
                required_hits=2 if not dry_run else 1,
                seed_id=seed.seed_id,
            )
            if anomaly.status in {"reproduced", "reproduction_pending", "observed_once"}:
                feedback["effective_mutations"] += 1
            if anomaly.status in {"reproduced", "reproduction_pending"}:
                if anomaly.status == "reproduced":
                    anomaly = minimize_candidate(
                        baseline_messages=baseline or case[:1],
                        candidate=anomaly,
                        play=play,
                        attempts=2 if not dry_run else 1,
                    )
                anomalies.append(anomaly.to_dict())
                feedback["candidate_anomalies"] += 1
                if deposit_dir and anomaly.status in {"reproduced", "minimized"}:
                    depositor = PocDepositor(deposit_dir)
                    manifest = depositor.build_manifest(
                        anomaly=anomaly,
                        campaign_id=campaign_id,
                        target_profile={
                            "transport": corpus.target.get("transport", "tcp"),
                            "port": port,
                            "ip": host,
                            "service_fingerprint": corpus.corpus_sha256,
                        },
                        state_path=seed.state_path,
                        baseline_probe=(baseline[0] if baseline else ""),
                    )
                    path = depositor.write_manifest(manifest)
                    manifests.append({"path": str(path), "manifest": manifest.to_dict(), "status": "candidate_poc"})
        if cases >= max_cases:
            break

    result["cases_executed"] = cases
    result["anomalies"] = anomalies
    result["manifests"] = manifests
    result["vulnerable"] = False
    result["note"] = (
        "campaign completed; candidate manifests written for human review"
        if manifests
        else "campaign completed with no strong oracle hits"
    )
    return result


def build_protocol_test_plan(
    *,
    task_index: int,
    target_port: int,
    profiles: list[str],
    gates: FuzzGateDecision,
    corpus_ref: str = "",
    reason: str = "",
) -> ProtocolTestPlan:
    return ProtocolTestPlan(
        task_index=task_index,
        target_port=target_port,
        mode=gates.mode,
        profiles=list(profiles),
        fuzz_enabled=gates.allowed,
        gate_reason=",".join(gates.reasons),
        corpus_ref=corpus_ref,
        reason=reason or gates.mode,
    )


def corpus_from_operator_payload(payload: dict[str, Any]) -> CorpusDocument:
    manager = CorpusManager()
    return manager.create_from_sessions(
        target=payload.get("target") or {},
        sessions=payload.get("sessions") or [],
        corpus_id=str(payload.get("corpus_id") or ""),
        source=str(payload.get("source") or "operator"),
    )


def corpus_from_params(params: dict[str, Any], *, target_ip: str = "", target_port: int | None = None) -> CorpusDocument | None:
    return resolve_corpus_for_params(params, target_ip=target_ip, target_port=target_port)

#!/usr/bin/env python3
"""Lab-only stateful fuzz validation for unknown TCP services.

This PoC never lets an LLM author attack code. It loads an operator-supplied
corpus, runs deterministic inference + field-aware mutation from
``protocol_research``, and deposits declarative replay manifests only.

Active fuzz requires Stage-04 gates AND allow_disruptive approval.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from iv_plugin_base import IVIVulnerabilityPlugin

SERVER_DIR = Path(__file__).resolve().parents[2]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from protocol_research.campaign import (  # noqa: E402
    evaluate_active_fuzz_gates,
    run_offline_inference,
    run_stateful_fuzz_campaign,
)
from protocol_research.corpus_resolver import resolve_corpus_for_params  # noqa: E402
from protocol_research.corpus_store import default_candidate_poc_dir  # noqa: E402


class UnknownProtocolStatefulFuzzPlugin(IVIVulnerabilityPlugin):
    meta_display_id = "POC-NET-016"
    meta_poc_name = "Unknown Protocol Stateful Fuzz Validation"
    meta_cve_id = "CWE-20"
    meta_source_url = "https://cwe.mitre.org/data/definitions/20.html"
    meta_references = [meta_source_url]
    meta_severity = "High"
    meta_protocol = "tcp"
    meta_target_os = ["all"]
    meta_required_params = ["target_ip", "target_port"]
    meta_optional_params = [
        "corpus",
        "corpus_json",
        "corpus_ref",
        "corpus_id",
        "allow_disruptive",
        "execution_mode",
        "lab_policy",
        "dry_run",
        "deposit_dir",
        "health",
    ]
    meta_profiles = ["network", "unknown_service", "lab_fuzz"]
    is_disruptive = True
    meta_destructive_level = "Restart"

    def check_prerequisites(self):
        if not self.target_ip:
            raise RuntimeError("target_ip is required")
        try:
            port = int(self.target_port)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("target_port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise RuntimeError("target_port must be between 1 and 65535")
        self.target_port = port
        return True

    def _load_corpus(self):
        params = self.params or {}
        doc = resolve_corpus_for_params(
            params,
            target_ip=str(self.target_ip or ""),
            target_port=int(self.target_port),
        )
        if doc is None:
            ref = str(params.get("corpus_ref") or params.get("corpus_id") or "").strip()
            if ref:
                raise RuntimeError(f"corpus_ref not found or target mismatch: {ref}")
            raise RuntimeError("corpus, corpus_json, or corpus_ref is required for stateful fuzz")
        return doc

    def exploit(self):
        params = self.params or {}
        allow = params.get("allow_disruptive") in (True, "true", "True", "1", 1)
        execution_mode = str(params.get("execution_mode") or "")
        lab_policy = params.get("lab_policy") in (True, "true", "True", "1", 1)
        dry_run = False
        if params.get("dry_run") in (True, "true", "True", "1", 1):
            dry_run = True

        try:
            corpus = self._load_corpus()
            has_corpus = True
        except Exception as exc:
            evidence = {
                "evidence_type": "protocol_fuzz_blocked",
                "error": str(exc)[:300],
                "conclusion": "No corpus — offline/fingerprint path only.",
            }
            self.results.update({
                "vulnerable": False,
                "description": "未知协议状态感知 Fuzz 因语料缺失被阻止",
                "evidence": json.dumps(evidence, ensure_ascii=False),
                "verification_status": "blocked_missing_corpus",
            })
            return self.results

        gates = evaluate_active_fuzz_gates(
            service_covered_by_existing_poc=bool(params.get("service_covered_by_existing_poc")),
            has_valid_seed_corpus=has_corpus,
            execution_mode=execution_mode,
            lab_policy=lab_policy,
            active_test_approved=allow,
        )

        if not gates.allowed or not allow:
            model = run_offline_inference(corpus)
            evidence = {
                "evidence_type": "protocol_offline_inference",
                "gates": gates.to_dict(),
                "model": model.to_dict(),
                "conclusion": (
                    "Active stateful fuzz denied. Offline format/state inference only. "
                    "Inference is probabilistic — not a vulnerability conclusion."
                ),
            }
            self.results.update({
                "vulnerable": False,
                "description": "未知协议离线推断（主动 Fuzz 未获门控批准）",
                "evidence": json.dumps(evidence, ensure_ascii=False),
                "verification_status": "offline_inference_only",
                "confidence": "informational",
            })
            return self.results

        deposit_dir = params.get("deposit_dir") or str(default_candidate_poc_dir())
        health = params.get("health") if isinstance(params.get("health"), dict) else {}
        campaign = run_stateful_fuzz_campaign(
            corpus=corpus,
            gates=gates,
            dry_run=dry_run,
            deposit_dir=str(deposit_dir),
            health=health,
        )
        evidence = {
            "evidence_type": "protocol_stateful_fuzz_campaign",
            "campaign": campaign,
            "conclusion": (
                "Campaign artifacts are candidate anomalies / declarative replay manifests. "
                "They are NOT confirmed CVEs and must not auto-register as PoCs."
            ),
        }
        self.results.update({
            "vulnerable": False,
            "description": "实验室状态感知 Fuzz 战役已执行（候选异常待人工审核）",
            "evidence": json.dumps(evidence, ensure_ascii=False),
            "verification_status": "candidate_anomalies_pending_review",
            "confidence": "informational",
            "requires_manual_review": bool(campaign.get("anomalies")),
        })
        return self.results


if __name__ == "__main__":
    print("Lab PoC: invoke via AutoSec sandbox with corpus + allow_disruptive + full_auto_lab")
    raise SystemExit(0)

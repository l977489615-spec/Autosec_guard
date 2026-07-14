"""Deposit declarative, immutable replay manifests — never auto-register Python."""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from .models import AnomalyCandidate, ReplayPocManifest


ALLOWED_STATUSES = {
    "candidate_poc",
    "reviewed",
    "registered",
}


class PocDepositor:
    def __init__(self, deposit_dir: str | Path) -> None:
        self.deposit_dir = Path(deposit_dir)
        self.deposit_dir.mkdir(parents=True, exist_ok=True)

    def build_manifest(
        self,
        *,
        anomaly: AnomalyCandidate,
        campaign_id: str,
        target_profile: dict[str, Any],
        state_path: list[str] | None = None,
        baseline_probe: str = "",
    ) -> ReplayPocManifest:
        if anomaly.status not in {"reproduced", "minimized", "candidate_poc"}:
            raise ValueError(f"anomaly status {anomaly.status} is not ready for deposition")
        messages = [
            {"direction": "client_to_server", "data_hex": hx}
            for hx in anomaly.messages_hex
        ]
        return ReplayPocManifest(
            schema_version="1.0",
            poc_id=f"CANDIDATE-{time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
            source_campaign_id=campaign_id,
            target_profile=dict(target_profile),
            preconditions=[
                "target is in isolated lab",
                "service is reachable",
                "session starts from disconnected state",
                "operator reviewed declarative replay before registration",
            ],
            state_path=list(state_path or []),
            messages=messages,
            oracle={
                "type": (anomaly.oracle_hits[0].split(":")[0] if anomaly.oracle_hits else "service_unavailable"),
                "hits": list(anomaly.oracle_hits),
                "baseline_probe": baseline_probe or (anomaly.messages_hex[0] if anomaly.messages_hex else ""),
                "failure_threshold_seconds": 5,
                "anomaly_score": anomaly.score,
            },
            reproduction={
                "attempts": int((anomaly.evidence or {}).get("attempts") or 3),
                "required_hits": 2,
                "status": anomaly.status,
            },
            status="candidate_poc",
        )

    def write_manifest(self, manifest: ReplayPocManifest) -> Path:
        path = self.deposit_dir / f"{manifest.poc_id}.json"
        payload = manifest.to_dict()
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        # companion .immutable marker with sha of content
        import hashlib

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        path.with_suffix(".sha256").write_text(digest + "\n", encoding="utf-8")
        return path

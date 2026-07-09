#!/usr/bin/env python3
"""在线可达性启发引导探测的 live 闭环实验（真实执行打 mock 服务）。

闭环：规划器据当前部分攻击图选下一个 PoC → 经 sandbox_runner 真实执行打 mock 车端服务
→ 观测真实 vulnerable 结果 → 并入已确认漏洞、更新多跳攻击图与可达前沿 → 再选，直至预算耗尽。
对照公平基线（严重度贪心、随机），在相同真实执行下比较攻击面覆盖与到物理影响的杀伤链。

用法：先 `python3 mock_vehicle_services.py --host 127.0.0.1 &`，再运行本脚本。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent
SERVER = LAB.parent / "server"
sys.path.insert(0, str(SERVER))

import assessment_engine as ae          # noqa: E402
import exploration_planner as ep        # noqa: E402
import poc_security as ps               # noqa: E402

TARGET = "127.0.0.1"
SANDBOX = SERVER / "sandbox_runner.py"
POCS_DIR = SERVER / "pocs"
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 1}


def real_execute(poc_rel: str) -> dict:
    """经 sandbox_runner 真实执行单个 PoC 打 mock，返回 {vulnerable, evidence}。"""
    poc_path = POCS_DIR / poc_rel
    env = dict(os.environ, AUTOSEC_TARGET_IP=TARGET, AUTOSEC_ALLOWED_HOSTS=TARGET)
    try:
        proc = subprocess.run(
            [sys.executable, str(SANDBOX), str(poc_path), json.dumps({"target_ip": TARGET})],
            capture_output=True, text=True, timeout=90, env=env,
        )
    except subprocess.TimeoutExpired:
        return {"vulnerable": False, "evidence": "", "error": "timeout"}
    out = proc.stdout or ""
    if "===RESULT_TOKEN===" in out:
        out = out.rsplit("===RESULT_TOKEN===", 1)[1]
    try:
        for line in reversed(out.strip().splitlines()):
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)
    except Exception:
        pass
    return {"vulnerable": False, "evidence": "", "error": "parse"}


def load_candidates(poc_rels: list[str]) -> list[dict]:
    pool = []
    for rel in poc_rels:
        meta = {"name": rel}
        p = POCS_DIR / rel
        if p.exists():
            prof = ps.extract_poc_security_profile(str(p))
            meta.update({"severity": prof.get("severity") or "Medium",
                         "destructive_level": prof.get("destructive_level") or "Safe",
                         "protocol": prof.get("protocol") or ""})
        pool.append(meta)
    return pool


def run_strategy(pool: list[dict], strategy: str, budget: int) -> dict:
    confirmed: list[dict] = []
    executed: list[dict] = []
    trace: list[dict] = []
    while len(executed) < budget:
        cands = [p for p in pool if p["name"] not in {e["name"] for e in executed}]
        if not cands:
            break
        if strategy == "guided":
            res = ep.next_exploration_actions(cands, confirmed, executed, top_k=1)
            if not res["actions"]:
                break
            poc = next(p for p in pool if p["name"] == res["actions"][0]["poc"])
        elif strategy == "severity":
            poc = sorted(cands, key=lambda p: SEV_RANK.get(str(p.get("severity", "")).lower(), 1),
                         reverse=True)[0]
        else:  # round-robin / 顺序
            poc = cands[0]
        executed.append(poc)
        dom = ep.classify_candidate(poc)["domain"]
        reachable = dom in ep.reachable_domains(confirmed)
        result = real_execute(poc["name"]) if reachable else {"vulnerable": False, "evidence": "",
                                                               "error": "domain_unreachable"}
        hit = bool(result.get("vulnerable")) and reachable
        if hit:
            confirmed.append({"name": poc["name"], "severity": poc.get("severity", "Medium"),
                              "vulnerable": True,
                              "details": (result.get("evidence") or "")[:200]})
        trace.append({"poc": poc["name"], "domain": dom, "reachable": reachable, "hit": hit})
    graph = ae.generate_multihop_attack_graph({"targetName": "MOCK-LOCAL", "results": confirmed})
    return {
        "strategy": strategy,
        "confirmed": len(confirmed),
        "kill_chains": graph["killChainCount"],
        "max_hops": max([p["hops"] for p in graph["paths"]] or [0]),
        "domains_explored": sorted({ep.classify_candidate(p)["domain"] for p in executed}),
        "trace": trace,
    }


def main() -> int:
    # 候选池：mock 可达的网络/侦察/诊断类 PoC（target_ip 驱动）
    candidate_rels = [
        "reconnaissance/02_CWE_200_TCP_Port_Scan_Reconnaissance.py",
        "reconnaissance/08_CWE_200_HTTP_Service_Enumeration_Reconnaissance.py",
        "network/02_CVE_2018_6242_ADB_Debug_Port_Active_Validation.py",
        "network/03_CWE_200_SSH_Service_Active_Validation.py",
        "network/06_CWE_319_Telnet_Service_Active_Validation.py",
        "network/09_CWE_306_MQTT_Unauth_Active_Validation.py",
        "network/10_CVE_2015_5611_Auth_Active_Validation.py",
        "network/11_CWE_200_RTSP_Log_Leak_Active_Validation.py",
        "canbus/poc134_doip_entity_status_probe.py",
        "canbus/poc135_doip_routing_activation_probe.py",
    ]
    pool = load_candidates(candidate_rels)
    budget = int(sys.argv[1]) if len(sys.argv) > 1 else 5

    print(f"=== Live 闭环实验（真实执行打 mock {TARGET}），候选 {len(pool)} 个 PoC，预算 {budget} 次探测 ===\n")
    results = {}
    for strat, label in [("sequential", "顺序探测"), ("severity", "严重度贪心(EDVV式)"),
                         ("guided", "在线图引导(本方案)")]:
        r = run_strategy(pool, strat, budget)
        results[strat] = r
        print(f"【{label}】确认漏洞 {r['confirmed']} | 杀伤链 {r['kill_chains']} | 最长链 {r['max_hops']} 跳")
        for t in r["trace"]:
            mark = "命中" if t["hit"] else ("不可达" if not t["reachable"] else "未中")
            print(f"    {t['poc']:45s} [{t['domain']:11s}] {mark}")
        print()

    print("=== 汇总 ===")
    print(f"{'策略':22s} {'确认':4s} {'杀伤链':6s} {'最长链':6s} 已探域")
    for strat in ("sequential", "severity", "guided"):
        r = results[strat]
        print(f"{strat:22s} {r['confirmed']:^4d} {r['kill_chains']:^6d} {r['max_hops']:^6d} {r['domains_explored']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

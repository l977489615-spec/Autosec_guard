#!/usr/bin/env python3
from execution_metrics import (
    classify_execution_item,
    evidence_rate_from_agent_report,
    has_archived_evidence,
    has_auditable_evidence,
    has_l2_archived_evidence,
)


def test_risky_without_substantive_passes_l2_but_fails_l3():
    item = {
        "status": "vulnerable",
        "vulnerable": True,
        "evidence": "",
        "branch_results": [
            {
                "success": True,
                "vulnerable": True,
                "trace_id": "agent_auto",
                "verification_status": "auto_confirmed_vulnerable",
            }
        ],
    }
    assert has_l2_archived_evidence(item)
    assert has_archived_evidence(item)
    assert not has_auditable_evidence(item)


def test_trace_only_completed_fails_l3():
    item = {
        "status": "completed",
        "vulnerable": False,
        "success": True,
        "branch_results": [{"success": True, "vulnerable": False, "trace_id": "agent_auto"}],
    }
    assert has_l2_archived_evidence(item)
    assert not has_auditable_evidence(item)


def test_risky_with_response_passes_l3():
    item = {
        "status": "vulnerable",
        "vulnerable": True,
        "evidence": "Host responds to ICMP",
        "branch_results": [
            {
                "success": True,
                "vulnerable": True,
                "trace_id": "agent_auto",
                "evidence": "Host responds to ICMP",
            }
        ],
    }
    assert has_archived_evidence(item)
    assert has_auditable_evidence(item)


def test_non_risky_completed_passes_without_extra():
    item = {
        "status": "completed",
        "vulnerable": False,
        "logs": ["done"],
        "success": True,
    }
    assert has_archived_evidence(item)
    assert has_auditable_evidence(item)


def test_reflector_skip_not_counted_without_execution():
    item = {"status": "skipped_by_reflector_reentry", "poc_name": "network/01.py"}
    assert classify_execution_item(item) == "not_executed"


def test_reflector_skip_counts_when_archive_has_evidence():
    report = {
        "structured": {
            "execution_archive": [
                {
                    "items": [
                        {
                            "poc_name": "network/01.py",
                            "status": "vulnerable",
                            "vulnerable": True,
                            "branch_results": [
                                {"success": True, "vulnerable": True, "trace_id": "agent_auto"}
                            ],
                        }
                    ]
                }
            ],
            "execution": {
                "items": [
                    {
                        "poc_name": "network/01.py",
                        "status": "skipped_by_reflector_reentry",
                    }
                ]
            },
        }
    }
    archived, completed, rate = evidence_rate_from_agent_report(report, auditable=False)
    assert archived == 1
    assert completed == 1
    assert rate == 1.0

    l5_archived, l5_completed, l5_rate = evidence_rate_from_agent_report(report, auditable=True)
    assert l5_completed == 1
    assert l5_rate == 0.0
    assert l5_archived == 0

    l3_archived, _, l3_rate = evidence_rate_from_agent_report(
        report,
        auditable=True,
        evidence_level="l3",
    )
    assert l3_rate == 0.0
    assert l3_archived == 0


if __name__ == "__main__":
    test_risky_without_substantive_passes_l2_but_fails_l3()
    test_risky_with_response_passes_l3()
    test_non_risky_completed_passes_without_extra()
    test_reflector_skip_not_counted_without_execution()
    test_reflector_skip_counts_when_archive_has_evidence()
    test_trace_only_completed_fails_l3()
    print("ok")

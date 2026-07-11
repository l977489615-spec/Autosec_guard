from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from agent_orchestrator import AgentOrchestrator, AssessmentReportGenerationError, is_local_assessment_report


class AssessmentResilienceTests(unittest.TestCase):
    def _orchestrator(self) -> AgentOrchestrator:
        orch = AgentOrchestrator.__new__(AgentOrchestrator)
        orch.target_ip = "192.0.2.10"
        orch.target_name = "test-target"
        orch.tester_name = "alice"
        orch.skip_assessment_report = False
        orch.findings = [{
            "poc_name": "network/read_only_probe.py",
            "vulnerable": True,
            "severity": "MEDIUM",
            "evidence": "service response confirmed",
        }]
        orch.structured_results = {
            "execution": {"items": [{
                "poc_name": "network/read_only_probe.py",
                "status": "completed",
                "vulnerable": True,
                "evidence": "service response confirmed",
            }]},
            "reflector": {"reentry_required": False, "evidence_sufficient": True},
            "capability_graph": {"nodes": [{"id": "service"}], "edges": []},
        }
        orch._add_log = mock.Mock()
        orch._has_user_supplied_attack_surface = mock.Mock(return_value=False)
        orch.llm_api_key = "configured"
        orch.llm_base_url = "https://example.invalid/v1"
        orch.report_model = "report-model"
        orch.llm_timeout_seconds = 30
        orch.llm_connect_timeout_seconds = 3
        return orch

    def test_timeout_raises_instead_of_local_fallback(self):
        orch = self._orchestrator()
        with mock.patch(
            "agent_orchestrator.QwenAgent.call",
            side_effect=RuntimeError("Read timed out (read timeout=120)"),
        ):
            with self.assertRaises(AssessmentReportGenerationError) as ctx:
                orch._run_assessment_phase(context="reentry transcript " * 5000)

        self.assertIn("远程评估模型未能生成完整 AI 报告", str(ctx.exception))
        assessment = orch.structured_results.get("assessment") or {}
        self.assertEqual(assessment.get("generation_mode"), "failed")
        self.assertNotIn("本地证据引擎生成", assessment.get("report_markdown") or "")

    def test_local_report_marker_detection(self):
        self.assertTrue(is_local_assessment_report("报告类型 | 本地确定性证据报告"))
        self.assertFalse(is_local_assessment_report("# 智能网联汽车安全评估报告\n\n## 1. 执行摘要"))

    def test_authoritative_evidence_precedes_bounded_transcript(self):
        orch = self._orchestrator()
        section_titles = [
            "执行摘要与评估边界", "测试范围、方法与覆盖", "确认漏洞总览", "漏洞详细分析与证据",
            "未确认项、失败项与测试限制", "分阶段整改与复测计划", "最终结论",
        ]
        headings = "\n\n".join(
            f"## {index}. {title}\n\n" + ("基于证据的评估内容。" * 40)
            for index, title in enumerate(section_titles, 1)
        )
        captured = {}

        def fake_call(prompt, context=""):
            captured["context"] = context
            return headings

        with mock.patch("agent_orchestrator.QwenAgent.call", side_effect=fake_call):
            report = orch._run_assessment_phase(context="old-phase-data-" * 5000)

        supplied = captured["context"]
        self.assertLess(len(supplied), 24000)
        self.assertLess(supplied.index("【权威执行结果(JSON)】"), supplied.index("【阶段摘要（非权威，已截断）】"))
        self.assertIn("service response confirmed", supplied)
        self.assertNotIn("【能力状态图(JSON)】", supplied)
        self.assertIn("执行摘要与评估边界", report)
        self.assertEqual(orch.structured_results["assessment"]["generation_mode"], "sectional_llm")


if __name__ == "__main__":
    unittest.main()

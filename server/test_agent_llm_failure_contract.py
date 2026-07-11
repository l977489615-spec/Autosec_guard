import unittest
from unittest import mock

import requests

from agent_orchestrator import QwenAgent, build_assessment_call, create_assessment_agent


class AgentLlmFailureContractTests(unittest.TestCase):
    def test_report_identity_uses_authenticated_tester_name(self):
        payload = build_assessment_call(
            target_ip='192.0.2.10',
            tester_name='alice',
            report_date='2026-07-11 18:00:00',
        )
        self.assertIn('【测试人】alice', payload['context'])
        self.assertIn('测试人必须写 alice', payload['prompt'])
        self.assertNotIn('BIOS团队', payload['context'] + payload['prompt'])

    def test_read_timeout_is_raised_instead_of_returned_as_report_text(self):
        agent = QwenAgent(
            '评估Agent', 'system', [], api_key='configured',
            base_url='https://example.invalid/v1', model_name='report-model',
        )
        with mock.patch('agent_orchestrator.time.sleep'), mock.patch(
            'agent_orchestrator.requests.post', side_effect=requests.ReadTimeout('slow model')
        ) as post:
            with self.assertRaisesRegex(RuntimeError, 'API 调用失败'):
                agent.call('build report')
        self.assertEqual(post.call_count, 3)

    def test_completion_request_has_bounded_output(self):
        agent = QwenAgent(
            '评估Agent', 'system', [], api_key='configured',
            base_url='https://example.invalid/v1', model_name='report-model',
            max_output_tokens=4096,
        )
        response = mock.Mock(status_code=200)
        response.json.return_value = {'choices': [{'message': {'content': 'ok'}}], 'usage': {}}
        with mock.patch('agent_orchestrator.requests.post', return_value=response) as post:
            self.assertEqual(agent.call('build report'), 'ok')
        self.assertEqual(post.call_args.kwargs['json']['max_tokens'], 4096)

    def test_streaming_completion_assembles_text_chunks(self):
        agent = QwenAgent(
            '评估Agent', 'system', [], api_key='configured',
            base_url='https://example.invalid/v1', model_name='report-model',
            max_output_tokens=4096, stream_responses=True, transport_retries=0,
        )
        response = mock.Mock(status_code=200)
        response.iter_lines.return_value = [
            'data: {"choices":[{"delta":{"content":"详细"}}]}',
            'data: {"choices":[{"delta":{"content":"报告"}}]}',
            'data: [DONE]',
        ]
        with mock.patch('agent_orchestrator.requests.post', return_value=response) as post:
            self.assertEqual(agent.call('build report'), '详细报告')
        self.assertTrue(post.call_args.kwargs['stream'])
        self.assertTrue(post.call_args.kwargs['json']['stream'])

    def test_disable_thinking_is_default_for_all_agents(self):
        agent = QwenAgent(
            '决策Agent', 'system', [], api_key='configured',
            base_url='https://example.invalid/v1', model_name='qwen-plus',
        )
        response = mock.Mock(status_code=200)
        response.json.return_value = {'choices': [{'message': {'content': 'ok'}}], 'usage': {}}
        with mock.patch('agent_orchestrator.requests.post', return_value=response) as post:
            self.assertEqual(agent.call('plan'), 'ok')
        self.assertFalse(post.call_args.kwargs['json']['enable_thinking'])

    def test_structured_agent_disables_thinking_on_aliyun_gateway(self):
        agent = QwenAgent(
            '反思Agent', 'system', [], api_key='configured',
            base_url='https://example.cn-beijing.maas.aliyuncs.com/compatible-mode/v1',
            model_name='reasoning-model', disable_thinking=True,
        )
        response = mock.Mock(status_code=200)
        response.json.return_value = {'choices': [{'message': {'content': '{"ok":true}'}}], 'usage': {}}
        with mock.patch('agent_orchestrator.requests.post', return_value=response) as post:
            self.assertEqual(agent.call('reflect'), '{"ok":true}')
        self.assertFalse(post.call_args.kwargs['json']['enable_thinking'])

    def test_empty_final_content_is_an_error_not_a_success_message(self):
        agent = QwenAgent(
            '反思Agent', 'system', [], api_key='configured',
            base_url='https://example.invalid/v1', model_name='reasoning-model',
            transport_retries=0, disable_thinking=True,
        )
        response = mock.Mock(status_code=200)
        response.json.return_value = {
            'choices': [{'message': {'content': '', 'reasoning_content': 'internal thoughts without JSON'}}],
            'usage': {},
        }
        with mock.patch('agent_orchestrator.requests.post', return_value=response):
            with self.assertRaisesRegex(RuntimeError, '空 content'):
                agent.call('reflect')

    def test_reasoning_json_is_recovered_when_content_is_empty(self):
        agent = QwenAgent(
            '决策Agent', 'system', [], api_key='configured',
            base_url='https://example.cn-beijing.maas.aliyuncs.com/compatible-mode/v1',
            model_name='reasoning-model', transport_retries=0,
        )
        response = mock.Mock(status_code=200)
        response.json.return_value = {
            'choices': [{
                'message': {
                    'content': '',
                    'reasoning_content': '思考过程...\n```json\n{"items": [{"poc_name": "network/demo.py"}]}\n```',
                },
            }],
            'usage': {},
        }
        with mock.patch('agent_orchestrator.requests.post', return_value=response) as post:
            result = agent.call('plan')
        self.assertIn('network/demo.py', result)
        self.assertEqual(post.call_count, 1)

    def test_assessment_agent_streams_and_does_not_repeat_long_timeout(self):
        agent = create_assessment_agent({
            'api_key': 'configured',
            'base_url': 'https://example.invalid/v1',
            'report_model': 'report-model',
        })
        self.assertTrue(agent._stream_responses)
        self.assertEqual(agent._transport_retries, 0)
        with mock.patch(
            'agent_orchestrator.requests.post', side_effect=requests.ReadTimeout('slow report')
        ) as post:
            with self.assertRaisesRegex(RuntimeError, 'API 调用失败'):
                agent.call('build report')
        self.assertEqual(post.call_count, 1)


if __name__ == '__main__':
    unittest.main()

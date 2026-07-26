import os
import sys
import tempfile
import unittest
import base64
import datetime
import json
import uuid
from dataclasses import replace
from unittest import mock
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


_DB_PATH = os.path.join(tempfile.gettempdir(), f'autosec-v3-test-{os.getpid()}.db')
os.environ['AUTOSEC_DB_URI'] = f'sqlite:///{_DB_PATH}'
os.environ['AUTOSEC_SECRET_KEY'] = 'test-session-secret-' + ('a' * 48)
os.environ['AUTOSEC_AI_CONFIG_KEY'] = 'test-ai-config-secret-' + ('b' * 48)
os.environ['AUTOSEC_BOOTSTRAP_MODE'] = 'edge'
os.environ['AUTOSEC_ALLOW_PRIVATE_AI_URL'] = 'true'

sys.path.insert(0, str(Path(__file__).resolve().parent))

import server as application  # noqa: E402
from licensing import LicenseManager, canonical_payload, format_utc  # noqa: E402
from sandbox_runner import _is_allowed_destination  # noqa: E402


class V3SecurityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        application.app.config.update(TESTING=True)
        with application.app.app_context():
            application.db.drop_all()
            application.db.create_all()

    @classmethod
    def tearDownClass(cls):
        with application.app.app_context():
            application.db.session.remove()
            application.db.drop_all()
        try:
            os.unlink(_DB_PATH)
        except FileNotFoundError:
            pass

    def setUp(self):
        self.client = application.app.test_client()
        response = self.client.post('/api/v1/auth/register', json={
            'username': 'admin',
            'password': 'correct-horse-battery-staple',
        })
        if response.status_code not in (201, 400, 403):
            self.fail(response.get_data(as_text=True))

    def login(self):
        return self.client.post('/api/v1/auth/login', json={
            'username': 'admin',
            'password': 'correct-horse-battery-staple',
        })

    def test_business_endpoints_reject_anonymous_requests(self):
        response = application.app.test_client().get('/api/v1/list_pocs')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json['error']['code'], 'AUTHENTICATION_REQUIRED')

    def test_invalid_license_blocks_authenticated_session_creation(self):
        self.assertEqual(self.login().status_code, 200)
        denied_manager = mock.Mock()
        denied_manager.feature_allowed.return_value = (False, {
            'state': 'expired',
            'message': '许可证已到期，请导入续期许可证。',
            'expires_at': '2026-07-01T00:00:00Z',
        })
        with mock.patch.object(application, 'LICENSE_MANAGER', denied_manager):
            response = self.client.post(
                '/api/v1/sessions',
                json={'mode': 'manual', 'target': {'ip': '127.0.0.1'}},
                headers={'Origin': 'http://localhost'},
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json['error']['code'], 'LICENSE_NOT_VALID')
        self.assertEqual(response.json['error']['details']['required_feature'], 'scan')

    def test_offline_license_can_be_activated_and_unlocks_session_creation(self):
        self.assertEqual(self.login().status_code, 200)
        with tempfile.TemporaryDirectory() as data_dir:
            private_key = Ed25519PrivateKey.generate()
            public_raw = private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            manager = LicenseManager(
                Path(data_dir),
                public_key_b64=base64.b64encode(public_raw).decode('ascii'),
                enforced=True,
            )
            now = datetime.datetime.now(datetime.timezone.utc)
            payload = {
                'schema': 1,
                'license_id': 'LIC-API-TEST',
                'customer': 'API Test Customer',
                'product': 'autosec-guard-edge',
                'edition': 'enterprise',
                'issued_at': format_utc(now),
                'not_before': format_utc(now - datetime.timedelta(minutes=1)),
                'expires_at': format_utc(now + datetime.timedelta(days=31)),
                'machine_code': manager.machine_code,
                'features': ['scan', 'poc_execution', 'report_export'],
                'key_id': 'test-key',
            }
            document = {
                'payload': payload,
                'signature': base64.b64encode(private_key.sign(canonical_payload(payload))).decode('ascii'),
            }
            with mock.patch.object(application, 'LICENSE_MANAGER', manager):
                self.assertEqual(self.client.get('/api/v1/license/status').json['state'], 'missing')
                activated = self.client.post(
                    '/api/v1/license/activate',
                    json={'license': document},
                    headers={'Origin': 'http://localhost'},
                )
                self.assertEqual(activated.status_code, 201, activated.get_data(as_text=True))
                self.assertTrue(activated.json['valid'])
                created = self.client.post(
                    '/api/v1/sessions',
                    json={'mode': 'manual', 'target': {'ip': '127.0.0.1'}},
                    headers={'Origin': 'http://localhost'},
                )
                self.assertEqual(created.status_code, 201, created.get_data(as_text=True))

    def test_every_v1_business_route_declares_authentication(self):
        public_endpoints = {'auth_status', 'register', 'login'}
        missing = []
        for rule in application.app.url_map.iter_rules():
            if not rule.rule.startswith('/api/v1/') or rule.endpoint in public_endpoints:
                continue
            view = application.app.view_functions[rule.endpoint]
            if not getattr(view, '_auth_required', False):
                missing.append(rule.rule)
        self.assertEqual(missing, [])

    def test_login_uses_httponly_strict_cookie(self):
        response = self.login()
        self.assertEqual(response.status_code, 200)
        cookie = response.headers.get('Set-Cookie', '')
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)
        self.assertNotIn('token', response.json)

    def test_stale_cookie_cannot_block_a_fresh_login(self):
        self.assertEqual(self.login().status_code, 200)
        relogin = self.client.post(
            '/api/v1/auth/login',
            json={'username': 'admin', 'password': 'correct-horse-battery-staple'},
            headers={'Origin': 'http://stale-origin.invalid'},
        )
        self.assertEqual(relogin.status_code, 200)
        protected_write = self.client.post(
            '/api/v1/sessions',
            json={'mode': 'manual', 'target': {'ip': '127.0.0.1'}},
            headers={'Origin': 'http://stale-origin.invalid'},
        )
        self.assertEqual(protected_write.status_code, 403)
        self.assertEqual(protected_write.json['error']['code'], 'ORIGIN_REJECTED')

    def test_registration_is_available_only_from_the_local_console(self):
        local = self.client.get('/api/v1/auth/status', base_url='http://localhost')
        self.assertTrue(local.json['registration_allowed'])
        self.assertEqual(local.json['registration_scope'], 'local')
        remote = self.client.get(
            '/api/v1/auth/status',
            base_url='http://192.168.50.10',
            environ_overrides={'REMOTE_ADDR': '192.168.50.11'},
        )
        self.assertFalse(remote.json['registration_allowed'])
        self.assertEqual(remote.json['registration_scope'], 'disabled')

    def test_network_bind_fails_closed_without_tls_and_bootstrap_protection(self):
        # Deliberately verifies that an all-interface bind fails closed.
        network_config = replace(application.CONFIG, flask_host='0.0.0.0')  # nosec B104
        with mock.patch.object(application, 'CONFIG', network_config), \
             mock.patch.object(application, '_BOOTSTRAP_MODE', 'edge'), \
             mock.patch.object(application, '_BOOTSTRAP_TOKEN', ''), \
             mock.patch.dict(os.environ, {'AUTOSEC_BEHIND_TLS': 'false'}, clear=False):
            with self.assertRaisesRegex(RuntimeError, 'BOOTSTRAP_MODE'):
                application._validate_startup_security()

    def test_password_change_persists_and_accepts_the_new_password(self):
        username = f'profile-{uuid.uuid4().hex[:10]}'
        old_password = 'correct-horse-battery-staple'
        new_password = 'new-correct-horse-battery-staple'
        created = self.client.post('/api/v1/auth/register', json={'username': username, 'password': old_password})
        self.assertEqual(created.status_code, 201)
        self.assertEqual(self.client.post('/api/v1/auth/login', json={'username': username, 'password': old_password}).status_code, 200)
        updated = self.client.put(
            '/api/v1/profile',
            json={'new_password': new_password},
            headers={'Origin': 'http://localhost'},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(self.client.get('/api/v1/profile').status_code, 401)
        relogin = application.app.test_client().post(
            '/api/v1/auth/login', json={'username': username, 'password': new_password}
        )
        self.assertEqual(relogin.status_code, 200)

    def test_non_admin_cannot_grant_disruptive_approval(self):
        username = f'operator-{uuid.uuid4().hex[:10]}'
        password = 'correct-horse-battery-staple'
        self.assertEqual(self.client.post('/api/v1/auth/register', json={
            'username': username, 'password': password,
        }).status_code, 201)
        self.assertEqual(self.client.post('/api/v1/auth/login', json={
            'username': username, 'password': password,
        }).status_code, 200)
        created = self.client.post(
            '/api/v1/sessions',
            json={'mode': 'manual', 'target': {'ip': '127.0.0.1'}},
            headers={'Origin': 'http://localhost'},
        )
        self.assertEqual(created.status_code, 201)
        response = self.client.post(
            f"/api/v1/sessions/{created.json['session']['id']}/approvals",
            json={'poc_filename': 'example.py', 'target': '127.0.0.1'},
            headers={'Origin': 'http://localhost'},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json['error']['code'], 'ADMIN_REQUIRED')

    def test_cli_password_reset_revokes_existing_browser_sessions(self):
        username = f'reset-{uuid.uuid4().hex[:10]}'
        old_password = 'correct-horse-battery-staple'
        new_password = 'reset-correct-horse-battery-staple'
        self.assertEqual(self.client.post('/api/v1/auth/register', json={
            'username': username,
            'password': old_password,
        }).status_code, 201)
        self.assertEqual(self.client.post('/api/v1/auth/login', json={
            'username': username,
            'password': old_password,
        }).status_code, 200)

        result = application.app.test_cli_runner().invoke(
            args=['reset-password', '--username', username, '--password', new_password]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.client.get('/api/v1/profile').status_code, 401)
        self.assertEqual(application.app.test_client().post('/api/v1/auth/login', json={
            'username': username,
            'password': new_password,
        }).status_code, 200)

    def test_ai_test_merges_saved_secret_with_visible_fields(self):
        username = f'ai-{uuid.uuid4().hex[:10]}'
        password = 'correct-horse-battery-staple'
        self.assertEqual(self.client.post('/api/v1/auth/register', json={'username': username, 'password': password}).status_code, 201)
        self.assertEqual(self.client.post('/api/v1/auth/login', json={'username': username, 'password': password}).status_code, 200)
        saved = self.client.put(
            '/api/v1/profile',
            json={'ai_config': {
                'base_url': 'http://127.0.0.1:18081/v1',
                'api_key': 'test-provider-key',
                'fast_model': 'test-fast-model',
            }},
            headers={'Origin': 'http://localhost'},
        )
        self.assertEqual(saved.status_code, 200)
        fake_response = mock.Mock(status_code=200)
        with mock.patch.object(application.requests, 'post', return_value=fake_response) as post:
            tested = self.client.post(
                '/api/v1/test-ai-config',
                json={'ai_config': {
                    'base_url': 'http://127.0.0.1:18081/v1',
                    'fast_model': 'test-fast-model',
                }},
                headers={'Origin': 'http://localhost'},
            )
        self.assertEqual(tested.status_code, 200)
        self.assertTrue(tested.json['success'])
        self.assertEqual(tested.json['model'], 'test-fast-model')
        self.assertEqual(post.call_args.kwargs['headers']['Authorization'], 'Bearer test-provider-key')

    def test_ai_key_is_encrypted_locally_masked_and_redacted_from_provider_errors(self):
        username = f'ai-private-{uuid.uuid4().hex[:8]}'
        password = 'correct-horse-battery-staple'
        api_key = f'customer-only-key-{uuid.uuid4().hex}'
        self.assertEqual(self.client.post('/api/v1/auth/register', json={
            'username': username, 'password': password,
        }).status_code, 201)
        self.assertEqual(self.client.post('/api/v1/auth/login', json={
            'username': username, 'password': password,
        }).status_code, 200)
        saved = self.client.put(
            '/api/v1/profile',
            json={'ai_config': {
                'base_url': 'http://127.0.0.1:18081/v1',
                'api_key': api_key,
                'fast_model': 'customer-model',
            }},
            headers={'Origin': 'http://localhost'},
        )
        self.assertEqual(saved.status_code, 200)
        self.assertNotIn(api_key, saved.get_data(as_text=True))
        self.assertEqual(saved.json['user']['ai_config']['apiKey'], '')
        self.assertTrue(saved.json['user']['ai_config']['apiKeyConfigured'])
        with application.app.app_context():
            record = application.UserAiConfig.query.join(application.User).filter(
                application.User.username == username
            ).first()
            self.assertIsNotNone(record)
            self.assertNotIn(api_key, record.encrypted_payload)
        fake_response = mock.Mock(status_code=401)
        fake_response.json.return_value = {
            'error': {'message': f'Authorization: Bearer {api_key} was rejected'}
        }
        fake_response.text = f'provider echoed {api_key}'
        with mock.patch.object(application.requests, 'post', return_value=fake_response):
            tested = self.client.post(
                '/api/v1/test-ai-config',
                json={'ai_config': {'fast_model': 'customer-model'}},
                headers={'Origin': 'http://localhost'},
            )
        self.assertEqual(tested.status_code, 502)
        self.assertNotIn(api_key, tested.get_data(as_text=True))
        sanitized = application._sanitize_provider_error(
            f'Authorization: Bearer {api_key} was rejected', api_key
        )
        self.assertNotIn(api_key, sanitized)
        self.assertIn('***REDACTED***', sanitized)

    def test_cli_token_is_scoped_persistent_and_revocable(self):
        login = self.client.post('/api/v1/auth/login', json={
            'username': 'admin',
            'password': 'correct-horse-battery-staple',
            'client_type': 'cli',
            'token_name': 'read-only-test',
            'scopes': ['poc:read'],
        })
        self.assertEqual(login.status_code, 200)
        self.assertNotIn('Set-Cookie', login.headers)
        raw_token = login.json['token']
        jti = login.json['token_info']['jti']
        headers = {'Authorization': f'Bearer {raw_token}'}
        self.assertEqual(self.client.get('/api/v1/list_pocs', headers=headers).status_code, 200)
        denied = self.client.post(
            '/api/v1/sessions', json={'mode': 'manual', 'target': {'ip': '127.0.0.1'}}, headers=headers
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json['error']['code'], 'TOKEN_SCOPE_REQUIRED')
        self.assertEqual(self.client.delete(f'/api/v1/api-tokens/{jti}', headers=headers).status_code, 200)
        self.assertEqual(self.client.get('/api/v1/list_pocs', headers=headers).status_code, 401)

    def test_cookie_write_requires_same_origin(self):
        self.login()
        rejected = self.client.post('/api/v1/sessions', json={'mode': 'manual', 'target': {'ip': '127.0.0.1'}})
        self.assertEqual(rejected.status_code, 403)
        accepted = self.client.post(
            '/api/v1/sessions',
            json={'mode': 'manual', 'target': {'ip': '127.0.0.1'}},
            headers={'Origin': 'http://localhost'},
        )
        self.assertEqual(accepted.status_code, 201)
        self.assertEqual(accepted.json['session']['status'], 'ready')

    def test_profile_update_accepts_loopback_origin_alias(self):
        self.login()
        updated = self.client.put(
            '/api/v1/profile',
            json={'ai_config': {'base_url': 'http://127.0.0.1:18081/v1', 'fast_model': 'test-fast-model'}},
            headers={'Origin': 'http://127.0.0.1'},
        )
        self.assertEqual(updated.status_code, 200)

    def test_profile_update_does_not_trust_forwarded_host_by_default(self):
        self.login()
        updated = self.client.put(
            '/api/v1/profile',
            json={'ai_config': {'base_url': 'http://127.0.0.1:18081/v1', 'fast_model': 'test-fast-model'}},
            headers={
                'Origin': 'http://127.0.0.1:3000',
                'X-Forwarded-Host': '127.0.0.1:3000',
                'X-Forwarded-Proto': 'http',
            },
        )
        self.assertEqual(updated.status_code, 403)
        self.assertEqual(updated.json['error']['code'], 'ORIGIN_REJECTED')

    def test_approval_grant_is_single_use_and_durable(self):
        self.login()
        with application.app.app_context():
            user = application.User.query.filter_by(username='admin').first()
            token = application._issue_disruptive_approval_token(
                'network/example.py', '127.0.0.1', user_id=user.id, session_id='session-1'
            )
            self.assertFalse(application._consume_disruptive_approval_token(
                token, 'network/example.py', '127.0.0.1', user.id, 'wrong-session'
            ))
            self.assertTrue(application._consume_disruptive_approval_token(
                token, 'network/example.py', '127.0.0.1', user.id, 'session-1'
            ))
            self.assertFalse(application._consume_disruptive_approval_token(
                token, 'network/example.py', '127.0.0.1', user.id, 'session-1'
            ))

    def test_sandbox_denies_network_without_a_target(self):
        self.assertFalse(_is_allowed_destination('127.0.0.1', set()))
        self.assertTrue(_is_allowed_destination('127.0.0.1', {'127.0.0.1'}))
        self.assertFalse(_is_allowed_destination('127.0.0.2', {'127.0.0.1'}))

    def test_hostname_is_resolved_and_pinned_to_authorized_ip(self):
        pinned, reason = application._pin_authorized_target('localhost')
        self.assertEqual(reason, 'ok')
        self.assertIn(pinned, {'127.0.0.1', '::1'})

    def test_server_owns_session_completion_transition(self):
        self.login()
        headers = {'Origin': 'http://localhost'}
        created = self.client.post(
            '/api/v1/sessions',
            json={'mode': 'batch', 'target': {'ip': '127.0.0.1'}},
            headers=headers,
        )
        session_id = created.json['session']['id']
        started = self.client.post(
            f'/api/v1/sessions/{session_id}/runs', json={}, headers=headers
        )
        self.assertEqual(started.json['session']['status'], 'running')
        completed = self.client.post(
            f'/api/v1/sessions/{session_id}/runs',
            json={'action': 'complete', 'result': {'confirmed_findings': 0}},
            headers=headers,
        )
        self.assertEqual(completed.json['session']['status'], 'completed')
        repeated = self.client.post(
            f'/api/v1/sessions/{session_id}/runs',
            json={'action': 'complete'},
            headers=headers,
        )
        self.assertEqual(repeated.status_code, 409)

    def test_session_cancel_terminates_registered_poc_worker(self):
        self.login()
        headers = {'Origin': 'http://localhost'}
        created = self.client.post(
            '/api/v1/sessions',
            json={'mode': 'batch', 'target': {'ip': '127.0.0.1'}},
            headers=headers,
        )
        session_id = created.json['session']['id']
        self.client.post(f'/api/v1/sessions/{session_id}/runs', json={}, headers=headers)

        worker = mock.Mock()
        plan = object()
        application._register_active_poc_plan(session_id, worker, plan)
        cancelled = self.client.post(
            f'/api/v1/sessions/{session_id}/runs',
            json={'action': 'cancel', 'result': {'reason': 'operator_cancelled'}},
            headers=headers,
        )

        self.assertEqual(cancelled.status_code, 200)
        self.assertEqual(cancelled.json['session']['status'], 'cancelled')
        self.assertEqual(cancelled.json['session']['result']['cancelled_workers'], 1)
        worker.cancel.assert_called_once_with(plan)

    def test_history_archive_does_not_complete_running_v3_session(self):
        self.login()
        headers = {'Origin': 'http://localhost'}
        created = self.client.post(
            '/api/v1/sessions',
            json={'mode': 'agent', 'target': {'ip': '127.0.0.1'}},
            headers=headers,
        )
        session_id = created.json['session']['id']
        self.client.post(f'/api/v1/sessions/{session_id}/runs', json={}, headers=headers)

        archived = self.client.post('/api/v1/save_session', json={
            'id': session_id,
            'targetName': 'Lifecycle Test',
            'connection': {'ip': '127.0.0.1'},
            'status': 'failed',
            'results': [],
            'logs': [],
            'riskScore': 0,
            'phase_records': [],
            'structured': {},
        }, headers=headers)
        self.assertEqual(archived.status_code, 201)

        with application.app.app_context():
            session = application.ScanSessionV3.query.filter_by(id=session_id).first()
            self.assertEqual(session.status, 'running')

    def test_new_agent_session_can_start_after_previous_run_is_archived(self):
        self.login()
        headers = {'Origin': 'http://localhost'}

        first = self.client.post(
            '/api/v1/sessions',
            json={'mode': 'agent', 'target': {'ip': '127.0.0.1'}},
            headers=headers,
        )
        first_id = first.json['session']['id']
        self.client.post(f'/api/v1/sessions/{first_id}/runs', json={}, headers=headers)
        completed = self.client.post(
            f'/api/v1/sessions/{first_id}/runs',
            json={'action': 'complete', 'result': {'confirmed_findings': 0}},
            headers=headers,
        )
        self.assertEqual(completed.status_code, 200)
        archived = self.client.post('/api/v1/save_session', json={
            'id': first_id,
            'targetName': 'First Run',
            'connection': {'ip': '127.0.0.1'},
            'status': 'completed',
            'results': [], 'logs': [], 'riskScore': 0,
            'phase_records': [], 'structured': {},
        }, headers=headers)
        self.assertEqual(archived.status_code, 201)

        second = self.client.post(
            '/api/v1/sessions',
            json={'mode': 'agent', 'target': {'ip': '127.0.0.1'}},
            headers=headers,
        )
        self.assertEqual(second.status_code, 201)
        self.assertNotEqual(second.json['session']['id'], first_id)
        started = self.client.post(
            f"/api/v1/sessions/{second.json['session']['id']}/runs",
            json={}, headers=headers,
        )
        self.assertEqual(started.status_code, 202)

    def test_reports_only_include_confirmed_findings(self):
        items = application._normalize_manual_execution_items({'results': [
            {'pocId': 'unconfirmed', 'vulnerable': True, 'verificationStatus': 'inconclusive'},
            {
                'pocId': 'confirmed',
                'vulnerable': True,
                'verificationStatus': 'manual_confirmed_vulnerable',
                'evidence': 'operator observation and target-side log',
            },
        ]})
        findings = application._normalize_manual_findings({'connection': {'ip': '127.0.0.1'}}, items)
        self.assertEqual([item['poc_name'] for item in findings], ['confirmed'])

    def test_manual_execution_preserves_negative_evidence(self):
        items = application._normalize_manual_execution_items({'results': [{
            'pocId': 'negative',
            'vulnerable': False,
            'verificationStatus': 'auto_confirmed_not_vulnerable',
            'evidence': 'service returned patched version 2.0.1',
        }]})
        self.assertEqual(items[0]['status'], 'completed')
        self.assertIs(items[0]['vulnerable'], False)
        self.assertEqual(items[0]['evidence'], 'service returned patched version 2.0.1')

    def test_confirmed_result_without_evidence_is_invalid(self):
        items = application._normalize_manual_execution_items({'results': [{
            'pocId': 'invalid',
            'vulnerable': True,
            'verificationStatus': 'auto_confirmed_vulnerable',
        }]})
        self.assertEqual(items[0]['status'], 'invalid_result')
        self.assertIsNone(items[0]['vulnerable'])

    def test_manual_confirmed_verdict_requires_recorded_evidence(self):
        self.login()
        rejected = self.client.post('/api/v1/poc_manual_verdict', json={
            'poc_id': 'demo.py',
            'verdict': 'confirmed_vulnerable',
        }, headers={'Origin': 'http://localhost'})
        self.assertEqual(rejected.status_code, 400)

        accepted = self.client.post('/api/v1/poc_manual_verdict', json={
            'poc_id': 'demo.py',
            'verdict': 'confirmed_vulnerable',
            'operator_note': 'target rebooted immediately after the trigger',
        }, headers={'Origin': 'http://localhost'})
        self.assertEqual(accepted.status_code, 200)
        self.assertTrue(accepted.json['evidence_contract_valid'])
        self.assertIn('target rebooted', accepted.json['evidence'])

    def test_legacy_scan_history_backfills_without_promoting_findings(self):
        with application.app.app_context():
            user = application.User.query.filter_by(username='admin').first()
            legacy_id = f'legacy-{uuid.uuid4()}'
            legacy = application.ScanHistory(
                user_id=user.id,
                session_id=legacy_id,
                target_ip='127.0.0.1',
                status='completed',
                results_json=json.dumps({'results': [{'vulnerable': True, 'details': 'legacy claim'}]}),
            )
            application.db.session.add(legacy)
            application.db.session.commit()
            expected_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'autosec-legacy:{legacy.id}:{legacy_id}'))
            application._backfill_v3_sessions()
            migrated = application.ScanSessionV3.query.filter_by(id=expected_id).first()
            self.assertIsNotNone(migrated)
            self.assertEqual(migrated.status, 'completed')
            artifacts = application.ExecutionArtifact.query.filter_by(session_id=expected_id).all()
            self.assertEqual(artifacts, [])


if __name__ == '__main__':
    unittest.main()

import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
from contextlib import redirect_stderr, redirect_stdout
from urllib.parse import parse_qs, urlsplit


spec = importlib.util.spec_from_file_location('updater_token', Path(__file__).with_name('dependency_updates_token.py'))
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class CredentialCallerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / 'output'
        self.output.touch()
        self.token = 'ghs_' + 'a' * 40
        self.env = {
            'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'etamong-playground/mcp-go',
            'GITHUB_REPOSITORY_ID': '1431206777', 'GITHUB_REPOSITORY_OWNER_ID': '295270411',
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
            'GITHUB_OUTPUT': str(self.output), 'GITHUB_WORKSPACE': str(self.root),
            'UPDATER_WRITE': 'false', 'UPDATER_BROKER_ORIGIN': 'https://broker.example',
            'UPDATER_AUDIENCE': 'https://hoopa.onul.me/dependency-updates',
            'ACTIONS_ID_TOKEN_REQUEST_URL': 'https://fixture.actions.githubusercontent.com/idtoken?api-version=2',
            'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'synthetic-request-credential',
        }
        self.calls = []
        self.masked = []

    def send(self, url, headers, data=None, method=None):
        self.calls.append((url, headers, data, method))
        if url.startswith('https://fixture.actions.githubusercontent.com/'):
            self.assertEqual(parse_qs(urlsplit(url).query)['audience'], [self.env['UPDATER_AUDIENCE']])
            self.assertEqual(headers['Authorization'], 'Bearer synthetic-request-credential')
            return 200, b'{"value":"synthetic-assertion"}'
        if url == 'https://broker.example/mint/ditto-github-token':
            self.assertEqual(headers['Authorization'], 'Bearer synthetic-assertion')
            self.assertTrue(self.record().is_file())
            return 201, self.token.encode() + b'\n'
        if url == 'https://api.github.com/installation/token':
            self.assertEqual(method, 'DELETE')
            self.assertEqual(headers['Authorization'], 'Bearer ' + self.token)
            return 204, b''
        self.fail('Unexpected credential destination')

    def record(self):
        return self.root / '.tmp/dependency-updates-operation.json'

    def mint(self):
        updater.mint(self.env, self.send, self.masked.append)

    def test_read_only_scope_and_credential_free_record(self):
        self.mint()
        body = json.loads(self.calls[1][2])
        self.assertEqual(body['repositories'], ['mcp-go'])
        self.assertEqual(body['permissions'], {'contents': 'read', 'pull_requests': 'read', 'statuses': 'read', 'issues': 'read'})
        self.assertRegex(body['operation_id'], r'^[0-9a-f]{32}$')
        self.assertEqual(json.loads(self.record().read_text()), body)
        self.assertNotIn(self.token, self.record().read_text())
        self.assertNotIn('synthetic-assertion', self.record().read_text())
        self.assertEqual(self.masked, ['::add-mask::' + self.token])
        self.assertEqual(self.output.read_text(), 'token=' + self.token + '\n')

    def test_write_scope_has_no_issue_or_workflow_write(self):
        self.env['UPDATER_WRITE'] = 'true'
        self.mint()
        self.assertEqual(json.loads(self.calls[1][2])['permissions'],
                         {'contents': 'write', 'pull_requests': 'write', 'statuses': 'write', 'issues': 'read'})

    def test_wrong_context_fails_before_network(self):
        for name in ['GITHUB_ACTIONS', 'GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY_OWNER_ID', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'UPDATER_WRITE', 'UPDATER_AUDIENCE']:
            with self.subTest(name=name):
                env = dict(self.env, **{name: 'wrong'})
                with self.assertRaises(updater.Failure):
                    updater.mint(env, self.send, self.masked.append)
        self.assertEqual(self.calls, [])

    def test_broker_origin_is_https_origin_only(self):
        for origin in ['', 'http://broker.example', 'https://user:password@broker.example', 'https://broker.example/path', 'https://broker.example?query=1', 'https://broker.example#fragment', 'https://broker.example\\path']:
            with self.subTest(origin=origin), self.assertRaises(updater.Failure):
                updater.mint(dict(self.env, UPDATER_BROKER_ORIGIN=origin), self.send, self.masked.append)
        self.assertEqual(self.calls, [])

    def test_existing_operation_is_not_replaced_or_redispatched(self):
        self.mint()
        original = self.record().read_bytes()
        self.calls.clear()
        with self.assertRaisesRegex(updater.Failure, 'existing_operation_requires_review'):
            self.mint()
        self.assertEqual(self.record().read_bytes(), original)
        self.assertEqual(self.calls, [])

    def test_lost_mint_response_does_not_retry(self):
        def lost(url, headers, data=None, method=None):
            if data is not None:
                self.calls.append((url, headers, data, method))
                raise updater.Failure('request_not_confirmed')
            return self.send(url, headers, data, method)
        with self.assertRaises(updater.Failure):
            updater.mint(self.env, lost, self.masked.append)
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(self.record().is_file())
        self.assertEqual(self.output.read_text(), '')
        self.assertEqual(self.masked, [])

    def test_status_only_replay_never_becomes_credential(self):
        def replay(url, headers, data=None, method=None):
            if data is not None:
                return 200, b'{"phase":"ok"}'
            return self.send(url, headers, data, method)
        with self.assertRaisesRegex(updater.Failure, 'issuance_not_confirmed'):
            updater.mint(self.env, replay, self.masked.append)
        self.assertEqual(self.output.read_text(), '')
        self.assertEqual(self.masked, [])

    def test_output_failure_revokes_before_returning(self):
        def broken_output(_):
            raise OSError('synthetic output failure')
        with self.assertRaisesRegex(updater.Failure, 'runtime_output_failed'):
            updater.mint(self.env, self.send, broken_output)
        self.assertEqual(self.calls[-1][0], 'https://api.github.com/installation/token')
        self.assertEqual(self.calls[-1][3], 'DELETE')

    def test_malformed_credential_is_never_published(self):
        for body in [b'short', b'x' * 4097, b'x' * 40 + b'\n\n', b'\xff' * 40]:
            with self.subTest(body_length=len(body)):
                def malformed(url, headers, data=None, method=None):
                    if data is not None:
                        return 201, body
                    return self.send(url, headers, data, method)
                with self.assertRaisesRegex(updater.Failure, 'provider_credential_response_refused'):
                    updater.mint(self.env, malformed, self.masked.append)
                self.assertEqual(self.output.read_text(), '')
                self.assertEqual(self.masked, [])
                self.record().unlink()

    def test_oidc_request_cannot_send_credential_to_other_host(self):
        self.env['ACTIONS_ID_TOKEN_REQUEST_URL'] = 'https://attacker.example/idtoken'
        with self.assertRaisesRegex(updater.Failure, 'oidc_endpoint_refused'):
            self.mint()
        self.assertEqual(self.calls, [])

    def test_redirect_is_rejected(self):
        with self.assertRaisesRegex(updater.Failure, 'redirect_refused'):
            updater.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://attacker.example')

    def test_cleanup_requires_confirmed_revocation(self):
        updater.revoke({'UPDATER_TOKEN': self.token}, self.send)
        with self.assertRaisesRegex(updater.Failure, 'revocation_not_confirmed'):
            updater.revoke({'UPDATER_TOKEN': self.token}, lambda *args, **kwargs: (500, b'synthetic private provider diagnostic'))

    def test_unexpected_error_has_no_raw_diagnostic(self):
        output, error = io.StringIO(), io.StringIO()
        with patch.object(updater, 'mint', side_effect=RuntimeError('synthetic private provider diagnostic')), patch.object(updater.sys, 'argv', ['caller', 'mint']), redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(updater.main(), 1)
        self.assertNotIn('synthetic private provider diagnostic', error.getvalue())
        self.assertEqual(output.getvalue(), '')


class TransportTests(unittest.TestCase):
    def test_transport_rejects_redirects_and_large_responses(self):
        destinations = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', '/destination')
                    self.end_headers()
                elif self.path == '/large':
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'x' * 16385)
                else:
                    destinations.append(self.path)
                    self.send_response(200)
                    self.end_headers()
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for path in ['/redirect', '/large']:
                with self.subTest(path=path), self.assertRaises(updater.Failure):
                    updater.request('http://127.0.0.1:' + str(server.server_port) + path, {'Authorization': 'Bearer synthetic-fixture'})
            self.assertEqual(destinations, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()

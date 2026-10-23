import io
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from werkzeug.security import generate_password_hash

from webapp import create_app, Job


class WebTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({'TESTING': True, 'SECRET_KEY': 'synthetic-session-key',
                               'LOGIN_USER': 'tester', 'PASSWORD_HASH': generate_password_hash('synthetic-password'),
                               'SESSION_COOKIE_SECURE': False})
        self.client = self.app.test_client()

    def tearDown(self):
        self.app.extensions['nodecheck_store'].close()

    def token(self):
        self.client.get('/login')
        with self.client.session_transaction() as s:
            return s['csrf']

    def login(self):
        return self.client.post('/login', data={'username': 'tester', 'password': 'synthetic-password', 'csrf': self.token()})

    def test_upload_requires_login_and_csrf(self):
        self.assertEqual(self.client.post('/api/jobs').status_code, 401)
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.post('/api/jobs', data={'file': (io.BytesIO(b'abc'), 'nodes.txt')}).status_code, 403)

    def test_wrong_password_does_not_authenticate(self):
        r = self.client.post('/login', data={'username': 'tester', 'password': 'wrong', 'csrf': self.token()})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.client.get('/api/jobs/no-such-job').status_code, 401)

    def test_private_proxy_is_rejected_and_credentials_not_echoed(self):
        self.login()
        with self.client.session_transaction() as s:
            token = s['csrf']
        r = self.client.post('/api/jobs', headers={'X-CSRF-Token': token},
            data={'file': (io.BytesIO(b'http://secret-user:secret-password@127.0.0.1:8080'), 'nodes.txt')})
        self.assertEqual(r.status_code, 400)
        self.assertNotIn(b'secret-password', r.data)

    def test_logout_erases_session_and_security_headers_disable_cache(self):
        self.login()
        with self.client.session_transaction() as s:
            token = s['csrf']
        r = self.client.post('/logout', data={'csrf': token})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get('/api/jobs/no-such-job').status_code, 401)
        self.assertIn('no-store', r.headers['Cache-Control'])

    def test_download_is_owner_scoped_and_consumes_results(self):
        self.login()
        with self.client.session_transaction() as s:
            owner, token = s['owner'], s['csrf']
        store = self.app.extensions['nodecheck_store']
        archive = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
        archive.close()
        with zipfile.ZipFile(archive.name, 'w') as output:
            output.writestr('available.txt', b'synthetic-result')
        store.jobs['synthetic-id'] = Job(owner=owner, total=1, state='done', archive_path=archive.name)
        other = self.app.test_client()
        other.get('/login')
        with other.session_transaction() as s:
            other_token = s['csrf']
        other.post('/login', data={'username': 'tester', 'password': 'synthetic-password', 'csrf': other_token})
        self.assertEqual(other.get('/api/jobs/synthetic-id').status_code, 404)
        result = self.client.post('/api/jobs/synthetic-id/download', headers={'X-CSRF-Token': token})
        self.assertEqual(result.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(result.data)) as archive:
            self.assertEqual(archive.read('available.txt'), b'synthetic-result')
        result.close()
        self.assertEqual(self.client.get('/api/jobs/synthetic-id').status_code, 404)

    def test_upload_accepts_multiple_files_and_deduplicates_nodes(self):
        self.login()
        with self.client.session_transaction() as s:
            token = s['csrf']
        response = self.client.post('/api/jobs', headers={'X-CSRF-Token': token}, data={
            'files': [(io.BytesIO(b'http://65.111.1.162:3128'), 'one.txt'),
                      (io.BytesIO(b'http://65.111.1.162:3128\nhttp://65.111.1.163:3128'), 'two.txt')],
            'protocol': 'http'}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json['total'], 2)
        self.app.extensions['nodecheck_store'].discard(response.json['id'])

    def test_completed_job_contains_unit_and_overall_exports(self):
        self.login()
        with self.client.session_transaction() as s:
            token = s['csrf']

        def fake_run(nodes, options, progress, stop=None):
            results = []
            for node in nodes:
                result = nc.classify(node, [nc.Check('https://example.test', True, 200, 5, '203.0.113.8')] * 3, 2)
                results.append(result)
                progress(result, len(results), len(nodes))
            return results

        import nodecheck as nc
        with patch('webapp.nc.run_checks', side_effect=fake_run):
            payload = '\n'.join(f'http://65.111.1.162:{12000 + index}' for index in range(101))
            response = self.client.post('/api/jobs', headers={'X-CSRF-Token': token}, data={
                'files': [(io.BytesIO(payload.encode()), 'nodes.txt')],
                'protocol': 'http', 'batch_size': '100'}, content_type='multipart/form-data')
            self.assertEqual(response.status_code, 202)
            job_id = response.json['id']
            for _ in range(20):
                status = self.client.get('/api/jobs/' + job_id).json
                if status['state'] == 'done':
                    break
                time.sleep(.01)
            self.assertEqual(status['state'], 'done')
            with self.client.post('/api/jobs/' + job_id + '/download', headers={'X-CSRF-Token': token}) as download:
                self.assertEqual(download.status_code, 200)
                with zipfile.ZipFile(io.BytesIO(download.data)) as archive:
                    names = set(archive.namelist())
                    self.assertIn('units/unit-0001/report.csv', names)
                    self.assertIn('units/unit-0002/report.csv', names)
                    self.assertIn('overall/report.csv', names)
                    self.assertIn('overall/clash.yaml', names)


if __name__ == '__main__':
    unittest.main()

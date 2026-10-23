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

    def completed_job(self, key='synthetic-id', **kwargs):
        with self.client.session_transaction() as s:
            owner = s['owner']
        archive_file = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
        archive_file.close()
        with zipfile.ZipFile(archive_file.name, 'w') as archive:
            archive.writestr('available.txt', b'synthetic-result')
        job = Job(owner=owner, total=1, state='done', archive_path=archive_file.name, **kwargs)
        self.app.extensions['nodecheck_store'].jobs[key] = job
        self.addCleanup(lambda: Path(archive_file.name).unlink(missing_ok=True))
        return job

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

    def test_download_is_owner_scoped_and_retained_until_confirmed_cleanup(self):
        self.login()
        with self.client.session_transaction() as s:
            owner, token = s['owner'], s['csrf']
        job = self.completed_job()
        store = self.app.extensions['nodecheck_store']
        store.jobs['unrelated-task'] = Job(owner='unrelated-account', total=1)
        self.assertEqual(self.client.get('/api/jobs/unrelated-task').status_code, 404)
        for _ in range(2):
            with self.client.post('/api/jobs/synthetic-id/download', headers={'X-CSRF-Token': token}) as result:
                self.assertEqual(result.status_code, 200)
                with zipfile.ZipFile(io.BytesIO(result.data)) as archive:
                    self.assertEqual(archive.read('available.txt'), b'synthetic-result')
            self.assertTrue(Path(job.archive_path).is_file())
            self.assertEqual(self.client.get('/api/jobs/synthetic-id').status_code, 200)
        archive_path = job.archive_path
        self.assertEqual(self.client.delete('/api/jobs/synthetic-id', headers={'X-CSRF-Token': token}).status_code, 200)
        self.assertFalse(Path(archive_path).exists())
        self.assertEqual(self.client.get('/api/jobs/synthetic-id').status_code, 404)

    def test_aborted_download_keeps_result_available_for_retry(self):
        self.login()
        job = self.completed_job()
        with self.client.session_transaction() as s:
            token = s['csrf']
        result = self.client.post('/api/jobs/synthetic-id/download', headers={'X-CSRF-Token': token}, buffered=False)
        result.close()  # Simulate a response closed before the client reads the ZIP.
        self.assertTrue(Path(job.archive_path).is_file())
        self.assertEqual(self.client.get('/api/jobs/synthetic-id').status_code, 200)

    def test_download_preparation_failure_preserves_job(self):
        self.login()
        job = self.completed_job()
        with self.client.session_transaction() as s:
            token = s['csrf']
        with patch('webapp.send_file', side_effect=OSError('synthetic read failure')):
            result = self.client.post('/api/jobs/synthetic-id/download', headers={'X-CSRF-Token': token})
        self.assertEqual(result.status_code, 500)
        self.assertTrue(Path(job.archive_path).is_file())
        self.assertEqual(self.client.get('/api/jobs/synthetic-id').status_code, 200)

    def test_active_result_retention_renews_and_exposes_expiry(self):
        self.login()
        job = self.completed_job(deadline=time.monotonic() + 60)
        before = job.deadline
        result = self.client.get('/api/jobs/synthetic-id')
        self.assertEqual(result.status_code, 200)
        self.assertGreaterEqual(result.json['expires_in_seconds'], 23 * 3600)
        self.assertGreater(job.deadline, before)

    def test_result_can_be_resumed_after_refresh_and_session_expiry(self):
        self.login()
        self.completed_job()
        result = self.client.get('/api/jobs/current')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json['id'], 'synthetic-id')
        with self.client.session_transaction() as s:
            s.clear()  # Expired browser session; do not explicitly log out.
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get('/api/jobs/current').json['id'], 'synthetic-id')

    def test_existing_authenticated_cookie_uses_same_account_for_new_tasks(self):
        self.login()
        with self.client.session_transaction() as s:
            owner = s['owner']
            s['owner'] = 'previous-session-random-id'
        self.client.get('/')
        with self.client.session_transaction() as s:
            self.assertEqual(s['owner'], owner)

    def test_summary_keeps_result_alive_without_resending_all_rows(self):
        self.login()
        job = self.completed_job(deadline=time.monotonic() + 60)
        job.rows = [{'endpoint': 'synthetic'}]
        result = self.client.get('/api/jobs/synthetic-id?summary=1')
        self.assertEqual(result.status_code, 200)
        self.assertNotIn('rows', result.json)
        self.assertNotIn('issues', result.json)
        self.assertGreaterEqual(result.json['expires_in_seconds'], 23 * 3600)

    def test_explicit_logout_deletes_current_archive(self):
        self.login()
        job = self.completed_job()
        archive_path = job.archive_path
        with self.client.session_transaction() as s:
            token = s['csrf']
        self.assertEqual(self.client.post('/logout', data={'csrf': token}).status_code, 302)
        self.assertFalse(Path(archive_path).exists())

    def test_idle_result_is_deleted_at_its_advertised_deadline(self):
        self.login()
        job = self.completed_job(deadline=time.monotonic() + 100)
        archive_path = job.archive_path
        with patch('webapp.time.monotonic', return_value=job.deadline + 1):
            self.app.extensions['nodecheck_store'].cleanup()
        self.assertFalse(Path(archive_path).exists())
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

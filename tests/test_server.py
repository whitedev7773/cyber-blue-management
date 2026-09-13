import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from aegis.server import Application, Handler, Store
class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.app = Application(Path(cls.temp.name) / 'runs.db')
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.app = cls.app
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.app.pool.shutdown()
        cls.temp.cleanup()
    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        mime = response.getheader('Content-Type')
        result = (response.status, json.loads(data) if mime.startswith('application/json') else data, dict(response.getheaders()))
        conn.close()
        return result
    def test_home_and_csp(self):
        code, data, headers = self.request('GET', '/')
        self.assertEqual(code, 200)
        self.assertIn(b'AEGIS', data)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
    def test_cross_origin_mutation_blocked(self):
        code, _, _ = self.request('POST', '/api/runs?name=x.json', b'{}', {'Origin':'https://untrusted.invalid','X-Aegis-Token':self.app.token})
        self.assertEqual(code, 403)
    def test_missing_token_blocked(self):
        self.assertEqual(self.request('POST', '/api/runs', b'{}')[0], 403)
    def test_host_validation(self):
        self.assertEqual(self.request('GET', '/api/session', headers={'Host':'untrusted.invalid'})[0], 403)
    def test_upload_review_export_delete(self):
        auth = {'X-Aegis-Token':self.app.token}
        code, result, _ = self.request('POST', '/api/runs?name=security.config.json', b'{}', auth)
        self.assertEqual(code, 202)
        key = result['id']
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            _, run, _ = self.request('GET', '/api/runs/' + key)
            if run['status'] not in ('queued', 'running'):
                break
            time.sleep(.01)
        self.assertEqual(run['status'], 'completed')
        code, changed, _ = self.request('POST', f'/api/runs/{key}/review', json.dumps({'finding_id':run['findings'][0]['id'], 'state':'deferred'}), auth)
        self.assertEqual(code, 200)
        self.assertEqual(changed['findings'][0]['review_status'], 'deferred')
        self.assertEqual(changed['review_history'][0]['to'], 'deferred')
        self.assertEqual(self.request('DELETE', '/api/runs/' + key, headers=auth)[0], 200)
        self.assertEqual(self.request('GET', '/api/runs/' + key)[0], 404)
    def test_invalid_review_body(self):
        self.assertEqual(self.request('POST', '/api/runs/unknown/review', b'[]', {'X-Aegis-Token':self.app.token})[0], 400)
    def test_static_path_traversal(self):
        self.assertEqual(self.request('GET', '/../aegis/server.py')[0], 404)
class PersistenceTests(unittest.TestCase):
    def test_restart_marks_interrupted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'db'
            first = Store(path)
            first.save({'id':'test', 'created':1, 'status':'running', 'name':'test'})
            self.assertEqual(Store(path).get('test')['status'], 'failed')

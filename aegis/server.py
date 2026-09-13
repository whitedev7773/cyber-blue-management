"""Loopback-only development server; Python standard library, no dependencies."""
import argparse
import json
import os
import secrets
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from .engine import MAX_UPLOAD, run_review

WEB = Path(__file__).resolve().parent.parent / 'web'

class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created REAL, body TEXT)')
            for key, raw in db.execute('SELECT id, body FROM runs').fetchall():
                item = json.loads(raw)
                if item['status'] in ('queued', 'running'):
                    item.update(status='failed', error='서버가 재시작되어 분석이 중단됐습니다. 다시 업로드하세요.')
                    db.execute('UPDATE runs SET body=? WHERE id=?', (json.dumps(item), key))
        os.chmod(self.path, 0o600)

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def save(self, item):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO runs VALUES (?, ?, ?)', (item['id'], item['created'], json.dumps(item, ensure_ascii=False)))

    def get(self, key):
        with self.connect() as db:
            row = db.execute('SELECT body FROM runs WHERE id=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self):
        with self.connect() as db:
            rows = db.execute('SELECT body FROM runs ORDER BY created DESC LIMIT 100').fetchall()
        return [{k: item.get(k) for k in ('id', 'name', 'created', 'status', 'coverage')} for item in map(lambda r: json.loads(r[0]), rows)]

    def delete(self, key):
        with self.connect() as db:
            db.execute('DELETE FROM runs WHERE id=?', (key,))

    def review(self, key, finding_id, state):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT body FROM runs WHERE id=?', (key,)).fetchone()
            if not row:
                raise ValueError('분석을 찾을 수 없습니다.')
            item = json.loads(row[0])
            if item['status'] != 'completed':
                raise ValueError('분석 완료 후 변경할 수 있습니다.')
            finding = next((f for f in item['findings'] if f['id'] == finding_id), None)
            if not finding:
                raise ValueError('발견 사항을 찾을 수 없습니다.')
            previous = finding['review_status']
            finding['review_status'] = state
            item.setdefault('review_history', []).append({'finding_id': finding_id, 'from': previous, 'to': state, 'time': time.time()})
            db.execute('UPDATE runs SET body=? WHERE id=?', (json.dumps(item, ensure_ascii=False), key))
        return item

class Application:
    def __init__(self, path):
        self.store = Store(path)
        self.token = secrets.token_urlsafe(32)
        self.slots = threading.BoundedSemaphore(2)
        self.pool = ThreadPoolExecutor(max_workers=2)

    def submit(self, name, data):
        if not self.slots.acquire(blocking=False):
            return None
        item = {'id': secrets.token_hex(12), 'name': name, 'created': time.time(), 'status': 'queued', 'events': []}
        try:
            self.store.save(item)
            self.pool.submit(self.work, item, data)
        except Exception:
            self.slots.release()
            raise
        return item['id']

    def work(self, item, data):
        try:
            item['status'] = 'running'
            self.store.save(item)
            def event(value):
                item['events'].append(value)
                self.store.save(item)
            result = run_review(item['name'], data, event)
            item.update(result)
        except ValueError as exc:
            item.update(status='failed', error=str(exc))
        except Exception:
            item.update(status='failed', error='분석 처리 오류가 발생했습니다. 파일 형식을 확인하세요.')
        finally:
            try:
                self.store.save(item)
            finally:
                self.slots.release()

class Handler(BaseHTTPRequestHandler):
    server_version = 'AegisReview'

    def log_message(self, *args):
        pass  # Uploaded names and report metadata do not enter request logs.

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    @property
    def app(self):
        return self.server.app

    def valid_host(self):
        return self.headers.get('Host') in {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}

    def send(self, code, value, mime='application/json; charset=utf-8'):
        raw = json.dumps(value, ensure_ascii=False).encode() if isinstance(value, (dict, list)) else value
        self.send_response(code)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(raw)

    def guard(self, mutate=False):
        if not self.valid_host():
            self.send(403, {'error': '로컬 Host만 허용됩니다.'})
            return False
        origin = self.headers.get('Origin')
        if origin and origin not in {f'http://127.0.0.1:{self.server.server_port}', f'http://localhost:{self.server.server_port}'}:
            self.send(403, {'error': '동일 출처 요청만 허용됩니다.'})
            return False
        if mutate and not secrets.compare_digest(self.headers.get('X-Aegis-Token', ''), self.app.token):
            self.send(403, {'error': '세션 토큰이 필요합니다. 페이지를 새로고침하세요.'})
            return False
        return True

    def do_GET(self):
        if not self.guard():
            return
        path = urlsplit(self.path).path
        if path == '/api/session':
            return self.send(200, {'token': self.app.token})
        if path == '/api/runs':
            return self.send(200, self.app.store.list())
        if path.startswith('/api/runs/'):
            item = self.app.store.get(path.removeprefix('/api/runs/'))
            return self.send(200 if item else 404, item or {'error': '분석을 찾을 수 없습니다.'})
        assets = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if path in assets:
            name, mime = assets[path]
            return self.send(200, (WEB / name).read_bytes(), mime)
        self.send(404, {'error': '찾을 수 없습니다.'})

    def body(self, limit):
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('청크 업로드는 지원하지 않습니다.')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise ValueError('잘못된 Content-Length입니다.') from None
        if length <= 0 or length > limit:
            raise ValueError('요청 크기 제한을 초과했거나 내용이 없습니다.')
        data = self.rfile.read(length)
        if len(data) != length:
            raise ValueError('업로드가 완료되지 않았습니다.')
        return data

    def do_POST(self):
        if not self.guard(mutate=True):
            return
        parsed = urlsplit(self.path)
        try:
            if parsed.path == '/api/runs':
                name = parse_qs(parsed.query).get('name', ['upload.zip'])[0]
                from .engine import safe_name
                safe_name(name)
                data = self.body(MAX_UPLOAD)
                key = self.app.submit(name, data)
                return self.send(202 if key else 429, {'id': key} if key else {'error': '동시 분석 2개가 실행 중입니다. 잠시 후 다시 시도하세요.'})
            if parsed.path.endswith('/review') and parsed.path.startswith('/api/runs/'):
                key = parsed.path.split('/')[3]
                value = json.loads(self.body(4096))
                if not isinstance(value, dict) or value.get('state') not in ('open', 'accepted', 'dismissed', 'deferred'):
                    raise ValueError('검토 상태가 올바르지 않습니다.')
                result = self.app.store.review(key, value.get('finding_id'), value['state'])
                return self.send(200, result)
            self.send(404, {'error': '찾을 수 없습니다.'})
        except (ValueError, UnicodeError, RecursionError) as exc:
            self.send(400, {'error': str(exc)[:250]})

    def do_DELETE(self):
        if not self.guard(mutate=True):
            return
        path = urlsplit(self.path).path
        if not path.startswith('/api/runs/'):
            return self.send(404, {'error': '찾을 수 없습니다.'})
        key = path.removeprefix('/api/runs/')
        item = self.app.store.get(key)
        if not item:
            return self.send(404, {'error': '분석을 찾을 수 없습니다.'})
        if item['status'] in ('running', 'queued'):
            return self.send(409, {'error': '실행 중인 분석은 삭제할 수 없습니다.'})
        self.app.store.delete(key)
        self.send(200, {'deleted': True})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--data', default='.aegis/reviews.sqlite3')
    args = parser.parse_args()
    app = Application(args.data)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    server.app = app
    print(f'Aegis Review: http://127.0.0.1:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.pool.shutdown(wait=True)

if __name__ == '__main__':
    main()

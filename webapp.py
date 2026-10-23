"""Authenticated, memory-only upload / check / download web application."""
from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from datetime import timedelta
import hmac
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import shutil
import socket
import threading
import tempfile
import time
import zipfile

from flask import Flask, Request, abort, after_this_request, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash

import nodecheck as nc

MAX_WEB_NODES = 50_000
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
ALLOWED_BATCH_SIZES = {100, 500}


def remove_archive(path):
    if path:
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            pass


class MemoryRequest(Request):
    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        return io.BytesIO()


@dataclass
class Job:
    owner: str
    total: int
    batch_size: int = 500
    deadline: float = field(default_factory=lambda: time.monotonic() + 86400)
    state: str = 'queued'
    done: int = 0
    usable: int = 0
    completed_units: int = 0
    rows: list = field(default_factory=list)
    archive_path: str = ''
    issues: list = field(default_factory=list)
    error: str = ''
    stop: threading.Event = field(default_factory=threading.Event)


class JobStore:
    def __init__(self):
        self.lock = threading.RLock()
        self.jobs = {}
        self.attempts = {}
        # One large batch at a time keeps CPU, memory, and egress bounded.
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix='nodecheck-job')
        self.closed = threading.Event()
        self.janitor = threading.Thread(target=self._sweep, daemon=True, name='nodecheck-expiry')
        self.janitor.start()

    def _sweep(self):
        while not self.closed.wait(10):
            self.cleanup()

    def cleanup(self):
        now = time.monotonic()
        with self.lock:
            for key, job in list(self.jobs.items()):
                if job.deadline <= now:
                    job.stop.set()
                    remove_archive(job.archive_path)
                    job.archive_path = ''
                    self.jobs.pop(key, None)
            self.attempts = {k: v for k, v in self.attempts.items() if v[1] > now}

    def discard(self, key):
        with self.lock:
            job = self.jobs.pop(key, None)
            if job:
                job.stop.set()
                remove_archive(job.archive_path)
                job.archive_path = ''
                job.rows.clear()

    def close(self):
        self.closed.set()
        for key in list(self.jobs):
            self.discard(key)
        self.pool.shutdown(wait=False, cancel_futures=True)


def public_node(node):
    """Pin proxy connections to a public IP, blocking local-network upload abuse."""
    cfg = node.config
    forbidden = {'dialer-proxy', 'interface-name', 'routing-mark', 'certificate', 'private-key',
                 'client-cert', 'client-key', 'ca-cert', 'ca-cert-path'}
    if forbidden.intersection(cfg):
        raise ValueError('网页端不接受本地证书、指定网卡或链式代理设置')
    host = cfg['server']
    try:
        addresses = {str(ipaddress.ip_address(host))}
    except ValueError:
        try:
            addresses = {r[4][0] for r in socket.getaddrinfo(host, cfg['port'], type=socket.SOCK_STREAM)}
        except OSError:
            raise ValueError('节点域名无法解析') from None
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError('网页端仅允许公网代理地址，禁止本机、内网及保留地址')
    address = sorted(addresses, key=lambda a: (':' in a, a))[0]
    if cfg.get('tls') and host != address:
        if node.protocol == 'http':
            cfg.setdefault('sni', host)
        else:
            cfg.setdefault('sni' if node.protocol in {'tuic', 'hysteria2'} else 'servername', host)
    cfg['server'] = address
    return node


def create_app(config=None):
    app = Flask(__name__)
    app.request_class = MemoryRequest
    app.config.update(
        SECRET_KEY=os.environ.get('APP_SECRET', ''),
        LOGIN_USER=os.environ.get('LOGIN_USER', ''),
        PASSWORD_HASH=os.environ.get('PASSWORD_HASH', ''),
        SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', 'true').lower() == 'true',
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        MAX_CONTENT_LENGTH=101 * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=101 * 1024 * 1024,
        MAX_FORM_PARTS=24,
        MIHOMO=os.environ.get('MIHOMO_PATH', shutil.which('mihomo') or ''),
    )
    app.config.update(config or {})
    if not all(app.config.get(k) for k in ('SECRET_KEY', 'LOGIN_USER', 'PASSWORD_HASH')):
        raise RuntimeError('请先用 python manage.py setup 配置登录账号')
    store = JobStore()
    app.extensions['nodecheck_store'] = store

    @app.before_request
    def guards():
        store.cleanup()
        if request.path.startswith('/static/') or request.path == '/healthz':
            return None
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(24)
        if request.path != '/login' and not session.get('owner'):
            if request.path.startswith('/api/'):
                return jsonify(error='请先登录'), 401
            return redirect(url_for('login'))
        if request.method in {'POST', 'DELETE'}:
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf', '')
            if not hmac.compare_digest(str(session.get('csrf', '')), str(token)):
                return jsonify(error='页面已过期，请刷新后重试'), 403
        return None

    @app.after_request
    def headers(response):
        response.headers.update({
            'Cache-Control': 'no-store, max-age=0', 'Pragma': 'no-cache',
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        })
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        messages = {413: '文件过大，请上传不超过 5 MB 的文件', 404: '任务不存在或已经清理', 429: '请求较多，请稍后再试'}
        return jsonify(error=messages.get(error.code, '请求无法处理')), error.code

    @app.errorhandler(Exception)
    def internal_error(error):
        # Never put uploaded content, credentials, or exception repr into logs.
        return jsonify(error='服务暂时无法处理，请稍后重试'), 500

    @app.route('/healthz')
    def health():
        return jsonify(status='ok')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if session.get('owner'):
            return redirect(url_for('index'))
        error = ''
        status = 200
        if request.method == 'POST':
            ip = request.remote_addr or 'unknown'
            with store.lock:
                count, expiry = store.attempts.get(ip, (0, time.monotonic() + 900))
            if count >= 8:
                return render_template('login.html', error='尝试次数较多，请 15 分钟后重试'), 429
            username = request.form.get('username', '')[:256]
            password = request.form.get('password', '')[:1024]
            valid_password = check_password_hash(app.config['PASSWORD_HASH'], password)
            if valid_password and hmac.compare_digest(username.encode(), app.config['LOGIN_USER'].encode()):
                session.clear()
                session.update(owner=secrets.token_urlsafe(32), csrf=secrets.token_urlsafe(24))
                session.permanent = True
                with store.lock:
                    store.attempts.pop(ip, None)
                return redirect(url_for('index'))
            with store.lock:
                if len(store.attempts) < 2048 or ip in store.attempts:
                    store.attempts[ip] = (count + 1, expiry)
            error, status = '账号或密码不正确', 401
        return render_template('login.html', error=error), status

    @app.route('/logout', methods=['POST'])
    def logout():
        owner = session.get('owner')
        with store.lock:
            for key, job in list(store.jobs.items()):
                if job.owner == owner:
                    store.discard(key)
        session.clear()
        return redirect(url_for('login'))

    @app.route('/')
    def index():
        return render_template('index.html', username=app.config['LOGIN_USER'])

    def execute(key, job, nodes):
        archive_path = ''
        aggregate_dir = ''
        try:
            curl = shutil.which('curl.exe' if os.name == 'nt' else 'curl')
            if not curl:
                raise ValueError('curl is unavailable')
            with store.lock:
                if key not in store.jobs or job.stop.is_set():
                    return
                job.state = 'running'
            options = nc.Options(timeout=8, workers=4, mihomo=app.config['MIHOMO'], curl=curl)
            temp_root = os.environ.get('TMPDIR') or tempfile.gettempdir()
            Path(temp_root).mkdir(parents=True, exist_ok=True)
            archive_handle = tempfile.NamedTemporaryFile(prefix='nodecheck-', suffix='.zip', dir=temp_root, delete=False)
            archive_path = archive_handle.name
            archive_handle.close()
            with store.lock:
                job.archive_path = archive_path

            aggregate_dir = tempfile.mkdtemp(prefix='nodecheck-aggregate-', dir=temp_root)
            aggregate_csv = Path(aggregate_dir) / 'report.csv'
            aggregate_json = Path(aggregate_dir) / 'report.json'
            aggregate_available = Path(aggregate_dir) / 'available.txt'
            first_csv = True
            exit_ips = set()
            clash_configs = []
            route_note = '从部署服务器发起真实 HTTP(S) 请求；2/3 检测通过记为可用。可用性不证明家宽归属。'
            with aggregate_json.open('w', encoding='utf-8') as json_stream:
                json_stream.write('{"route_note":')
                json.dump(route_note, json_stream, ensure_ascii=False)
                json_stream.write(',"results":[')
                json_first = True
                with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                    for unit_index, offset in enumerate(range(0, len(nodes), job.batch_size), 1):
                        if job.stop.is_set():
                            return
                        batch_nodes = nodes[offset:offset + job.batch_size]
                        batch_rows = []
                        def progress(result, done, total):
                            with store.lock:
                                if not job.stop.is_set():
                                    public = result.public()
                                    batch_rows.append(public)
                                    job.done = offset + done
                                    job.usable += int(result.usable)
                                    job.rows = batch_rows[-job.batch_size:]
                        results = nc.run_checks(batch_nodes, options, progress, job.stop)
                        if job.stop.is_set():
                            return
                        unit_files = nc.export_files(results, job.issues if unit_index == 1 else [], route_note)
                        unit_root = f'units/unit-{unit_index:04d}/'
                        for filename, content in unit_files.items():
                            archive.writestr(unit_root + filename, content)
                        csv_text = unit_files['report.csv'].decode('utf-8-sig')
                        csv_lines = csv_text.splitlines(keepends=True)
                        with aggregate_csv.open('a', encoding='utf-8-sig' if first_csv else 'utf-8', newline='') as stream:
                            stream.writelines(csv_lines if first_csv else csv_lines[1:])
                        first_csv = False
                        with aggregate_available.open('ab') as stream:
                            stream.write(unit_files['available.txt'])
                        for result in results:
                            record = result.public()
                            # report.json is streamed so 50k rows do not stay in RAM.
                            if not json_first:
                                json_stream.write(',')
                            json.dump(record, json_stream, ensure_ascii=False)
                            json_first = False
                            if result.usable:
                                cfg = dict(result.node.config)
                                cfg['name'] = f'usable-{len(clash_configs) + 1:05d}'
                                clash_configs.append(cfg)
                                exit_ips.update(ip for ip in record['exit_ips'] if ip)
                        with store.lock:
                            job.completed_units = unit_index
                json_stream.write('],"parse_issues":')
                json.dump(job.issues, json_stream, ensure_ascii=False)
                json_stream.write('}')
            with zipfile.ZipFile(archive_path, 'a', zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                for path in (aggregate_csv, aggregate_json, aggregate_available):
                    archive.write(path, 'overall/' + path.name)
                archive.writestr('overall/exit_ips.txt', ('\n'.join(sorted(exit_ips)) + ('\n' if exit_ips else '')).encode())
                if nc.yaml:
                    archive.writestr('overall/clash.yaml', nc.yaml.safe_dump({'proxies': clash_configs}, allow_unicode=True, sort_keys=False).encode())
                else:
                    archive.writestr('overall/clash.json', json.dumps({'proxies': clash_configs}, ensure_ascii=False).encode())
                archive.writestr('overall/NOTES.txt', (route_note + f'\n检测单位：每 {job.batch_size} 个节点一个单元；单元文件位于 units/。\n').encode())
            shutil.rmtree(aggregate_dir, ignore_errors=True)
            with store.lock:
                if key in store.jobs and not job.stop.is_set():
                    job.completed_units = math.ceil(len(nodes) / job.batch_size)
                    job.state = 'done'
                    job.deadline = time.monotonic() + 900
        except Exception:
            if archive_path:
                remove_archive(archive_path)
            with store.lock:
                job.archive_path = ''
                job.state = 'error'
                job.error = '测试未能完成，请清理任务后重试'
                job.deadline = time.monotonic() + 300
        finally:
            if aggregate_dir:
                shutil.rmtree(aggregate_dir, ignore_errors=True)

    @app.route('/api/jobs', methods=['POST'])
    def upload():
        owner = session['owner']
        with store.lock:
            if len(store.jobs) >= 2:
                return jsonify(error='测试资源正在使用中，请稍后重试'), 429
            if any(j.owner == owner for j in store.jobs.values()):
                return jsonify(error='请先下载或清理当前任务'), 409
            uploads = request.files.getlist('files') or request.files.getlist('file')
            if not uploads:
                return jsonify(error='请选择节点文件'), 400
            try:
                protocol = request.form.get('protocol', 'http')
                if protocol not in {'http', 'socks5'}:
                    raise ValueError('裸节点协议无效')
                if len(uploads) > 20:
                    raise ValueError('单次最多上传 20 个文件')
                try:
                    batch_size = int(request.form.get('batch_size', '500'))
                except ValueError:
                    raise ValueError('检测单位只能是 100 或 500') from None
                if batch_size not in ALLOWED_BATCH_SIZES:
                    raise ValueError('检测单位只能是 100 或 500')
                parsed = nc.Parsed()
                total_bytes = 0
                for upload_file in uploads:
                    filename = upload_file.filename or 'nodes.txt'
                    if Path(filename).suffix.lower() not in {'.txt', '.md', '.csv', '.json', '.yaml', '.yml', '.docx'}:
                        raise ValueError('支持 TXT、MD、CSV、JSON、YAML、DOCX 文件')
                    data = upload_file.read(nc.MAX_BYTES + 1)
                    total_bytes += len(data)
                    if total_bytes > MAX_UPLOAD_BYTES:
                        raise ValueError('本次上传总大小不能超过 100 MB')
                    current = nc.read_document(data, filename, protocol)
                    parsed.nodes.extend(current.nodes)
                    parsed.issues.extend(current.issues)
                # Multiple source files may contain the same node; retain one copy.
                unique = {}
                for node in parsed.nodes:
                    unique.setdefault(node.key, node)
                parsed.nodes = list(unique.values())
                if not parsed.nodes:
                    raise ValueError('没有识别到节点，请检查文档格式')
                if len(parsed.nodes) > MAX_WEB_NODES:
                    raise ValueError('单次最多测试 50000 个去重节点，请拆分任务')
                nodes = []
                for node in parsed.nodes:
                    try:
                        nodes.append(public_node(node))
                    except ValueError as error:
                        parsed.issues.append(f'第 {node.line} 项：{error}')
                if not nodes:
                    raise ValueError('未找到可测试的公网节点；请检查 IP 或域名。')
            except ValueError as error:
                return jsonify(error=str(error)), 400
            key = secrets.token_urlsafe(24)
            job = Job(owner=owner, total=len(nodes), batch_size=batch_size, issues=parsed.issues)
            store.jobs[key] = job
            store.pool.submit(execute, key, job, nodes)
        return jsonify(id=key, total=job.total, issues=job.issues), 202

    def owned_job(key):
        job = store.jobs.get(key)
        if job is None or job.owner != session['owner']:
            abort(404)
        return job

    @app.route('/api/jobs/<key>')
    def status(key):
        with store.lock:
            job = owned_job(key)
            return jsonify(state=job.state, total=job.total, done=job.done, usable=job.usable,
                           batch_size=job.batch_size, total_units=math.ceil(job.total / job.batch_size),
                           completed_units=job.completed_units, rows=job.rows, issues=job.issues, error=job.error)

    @app.route('/api/jobs/<key>/download', methods=['POST'])
    def download(key):
        with store.lock:
            job = owned_job(key)
            if job.state != 'done':
                return jsonify(error='任务尚未完成'), 409
            archive_path = job.archive_path
            if not archive_path or not Path(archive_path).is_file():
                return jsonify(error='结果文件已清理，请重新检测'), 410
            store.jobs.pop(key, None)
            job.archive_path = ''
            job.rows.clear()
        @after_this_request
        def cleanup(response):
            remove_archive(archive_path)
            return response
        return send_file(archive_path, mimetype='application/zip', as_attachment=True, download_name='nodecheck-results.zip', max_age=0)

    @app.route('/api/jobs/<key>', methods=['DELETE'])
    def discard(key):
        with store.lock:
            owned_job(key)
            store.discard(key)
        return jsonify(ok=True)

    return app

"""Portable proxy document parser, real request checker, and result exporter."""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import contextlib
import copy
import csv
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, quote, unquote, urlsplit
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_TARGETS = ('https://api.ipify.org?format=json',
                   'https://www.cloudflare.com/cdn-cgi/trace',
                   'https://www.gstatic.com/generate_204')
PROTOCOLS = {'http', 'socks5', 'socks4', 'socks4a', 'ss', 'vmess', 'vless',
             'trojan', 'hysteria2', 'tuic'}
LINK_RE = re.compile(r'(?i)\b(?:https?|socks(?:4a?|5h?)?|ssr?|vmess|vless|trojan|hy2|hysteria2|tuic)://[^\s<>"\u3000，；。]+')
MAX_BYTES = 5 * 1024 * 1024


@dataclass
class Node:
    config: dict
    source: str
    line: int = 0
    share: str = ''

    @property
    def protocol(self):
        return self.config['type']

    @property
    def label(self):
        host = self.config['server']
        return f'{self.protocol}://{bracket(host)}:{self.config["port"]}'

    @property
    def key(self):
        cfg = {k: v for k, v in self.config.items() if k != 'name'}
        return hashlib.sha256(json.dumps(cfg, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def direct_url(self):
        allowed = {'name', 'type', 'server', 'port', 'username', 'password', 'udp'}
        if self.protocol not in {'http', 'socks5', 'socks4', 'socks4a'}:
            return None
        if set(self.config) - allowed - {'tls'}:
            return None
        scheme = self.protocol
        if scheme == 'http' and self.config.get('tls'):
            scheme = 'https'
        if scheme == 'socks5':
            scheme = 'socks5h'
        auth = ''
        if 'username' in self.config or 'password' in self.config:
            auth = quote(str(self.config.get('username', '')), safe='') + ':'
            auth += quote(str(self.config.get('password', '')), safe='') + '@'
        return f'{scheme}://{auth}{bracket(self.config["server"])}:{self.config["port"]}'


@dataclass
class Parsed:
    nodes: list = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


def bracket(host):
    return f'[{host}]' if ':' in host else host


def decode64(value):
    value = re.sub(r'\s+', '', value)
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode('utf-8-sig')


def transport(cfg, network, params):
    network = network or 'tcp'
    if network == 'tcp':
        return
    if network not in {'ws', 'grpc', 'h2', 'http', 'httpupgrade'}:
        raise ValueError('不支持的传输类型')
    cfg['network'] = network
    if network in {'ws', 'httpupgrade'}:
        opts = {'path': params.get('path', '/')}
        if params.get('host'):
            opts['headers'] = {'Host': params['host']}
        cfg[network + '-opts'] = opts
    elif network == 'grpc':
        cfg['grpc-opts'] = {'grpc-service-name': params.get('serviceName', params.get('path', ''))}
    else:
        cfg[network + '-opts'] = {'path': [params.get('path', '/')],
                                 'host': [params.get('host', cfg['server'])]}


def parse_link(link, source, line):
    scheme = link.split('://', 1)[0].lower()
    if scheme == 'vmess':
        v = json.loads(decode64(link.split('://', 1)[1]))
        cfg = {'type': 'vmess', 'server': v['add'], 'port': v['port'], 'uuid': v['id'],
               'alterId': int(v.get('aid', 0)), 'cipher': v.get('scy', 'auto'),
               'tls': v.get('tls') == 'tls'}
        if v.get('sni'):
            cfg['servername'] = v['sni']
        transport(cfg, v.get('net', 'tcp'), v)
        return validate_node(Node(cfg, source, line, link))
    if scheme == 'ss':
        body = link.split('://', 1)[1].split('#', 1)[0]
        if '@' not in body:
            link = 'ss://' + decode64(body)
    u = urlsplit(link)
    p = {k: v[-1] for k, v in parse_qs(u.query).items()}
    kind = {'https': 'http', 'socks': 'socks5', 'socks5h': 'socks5', 'hy2': 'hysteria2'}.get(scheme, scheme)
    if kind not in PROTOCOLS:
        raise ValueError('不支持的协议')
    cfg = {'type': kind, 'server': u.hostname, 'port': u.port}
    user = unquote(u.username or '')
    password = unquote(u.password or '')
    if kind in {'http', 'socks5', 'socks4', 'socks4a'}:
        if u.username is not None:
            cfg.update(username=user, password=password)
        if scheme == 'https':
            cfg['tls'] = True
    elif kind == 'ss':
        if u.password is None:
            user, password = decode64(user).split(':', 1)
        cfg.update(cipher=user, password=password)
        if p.get('plugin'):
            parts = p['plugin'].split(';')
            plugin = parts[0]
            if plugin not in {'obfs-local', 'simple-obfs', 'v2ray-plugin'}:
                raise ValueError('不支持的 SS 插件')
            cfg['plugin'] = 'obfs' if plugin in {'obfs-local', 'simple-obfs'} else plugin
            opts = dict(s.split('=', 1) if '=' in s else (s, True) for s in parts[1:])
            cfg['plugin-opts'] = {('mode' if k == 'obfs' else 'host' if k == 'obfs-host' else k): v for k, v in opts.items()}
    elif kind in {'vless', 'trojan'}:
        cfg['uuid' if kind == 'vless' else 'password'] = user
        if p.get('encryption', 'none') != 'none':
            raise ValueError('不支持的 VLESS 加密参数')
        if p.get('flow'):
            cfg['flow'] = p['flow']
        cfg['tls'] = p.get('security', 'tls' if kind == 'trojan' else 'none') in {'tls', 'reality'}
        if p.get('security') == 'reality':
            cfg['reality-opts'] = {'public-key': p['pbk'], 'short-id': p.get('sid', '')}
        if p.get('fp'):
            cfg['client-fingerprint'] = p['fp']
        transport(cfg, p.get('type', 'tcp'), p)
    elif kind == 'hysteria2':
        cfg['password'] = user + (':' + password if u.password is not None else '')
        cfg['tls'] = True
        if p.get('obfs'):
            cfg['obfs'] = p['obfs']
            cfg['obfs-password'] = p.get('obfs-password', '')
    elif kind == 'tuic':
        cfg.update(uuid=user, password=password)
        cfg['tls'] = True
        for param in ('congestion_control', 'udp_relay_mode'):
            if param in p:
                cfg[param.replace('_', '-')] = p[param]
    if kind not in {'http', 'socks5', 'socks4', 'socks4a'}:
        if p.get('sni') or p.get('peer'):
            cfg['sni' if kind in {'hysteria2', 'tuic'} else 'servername'] = p.get('sni', p.get('peer'))
        if p.get('alpn'):
            cfg['alpn'] = p['alpn'].split(',')
        if p.get('allowInsecure', p.get('insecure')) in {'1', 'true'}:
            cfg['skip-cert-verify'] = True
    return validate_node(Node(cfg, source, line, link))


def validate_node(node):
    cfg = node.config
    cfg['type'] = str(cfg.get('type', '')).lower()
    if cfg['type'] not in PROTOCOLS:
        raise ValueError('不支持的协议')
    host = str(cfg.get('server', '')).strip()
    if not host or any(c.isspace() or c in '/\\@\r\n' for c in host) or len(host) > 253:
        raise ValueError('节点地址无效')
    port = int(cfg['port'])
    if not 1 <= port <= 65535:
        raise ValueError('节点端口无效')
    if cfg.get('dialer-proxy'):
        raise ValueError('链式节点须先展开为独立节点')
    cfg.update(server=host, port=port)
    cfg.pop('name', None)
    json.dumps(cfg, allow_nan=False)
    return node


def parse_document(text: str, source: str = 'input.txt', default_protocol='http') -> Parsed:
    parsed = Parsed()
    seen = set()
    def add(node):
        if node.key not in seen:
            seen.add(node.key)
            parsed.nodes.append(node)

    def issue(line, message='无法解析该节点，请检查格式和参数'):
        parsed.issues.append(f'{Path(source).name}:{line}: {message}')

    # Only extract proxy entries. Never run the document's ports, rules, or URLs.
    structured = None
    stripped = text.strip('\ufeff \r\n\t')
    try:
        if stripped.startswith(('{', '[')):
            structured = json.loads(stripped)
        elif Path(source).suffix.lower() in {'.yaml', '.yml'} or re.search(r'^proxies:\s*$', text, re.M):
            if yaml is None:
                raise ValueError('YAML 格式需要安装 PyYAML')
            structured = yaml.safe_load(stripped)
        if isinstance(structured, dict) and isinstance(structured.get('proxies'), list):
            structured = structured['proxies']
        elif isinstance(structured, dict) and 'server' in structured and 'type' in structured:
            structured = [structured]
        if isinstance(structured, list):
            for i, item in enumerate(structured, 1):
                if isinstance(item, dict):
                    try:
                        add(validate_node(Node(copy.deepcopy(item), source, i)))
                    except (ValueError, KeyError, TypeError, RecursionError):
                        issue(i)
                elif isinstance(item, str):
                    part = parse_document(item, source + '.txt', default_protocol)
                    for node in part.nodes:
                        add(node)
                    parsed.issues.extend(part.issues)
            return parsed
    except (ValueError, TypeError, RecursionError, Exception if yaml is None else yaml.YAMLError):
        issue(0, '结构化文档解析失败（内容未写入日志）')
        if Path(source).suffix.lower() in {'.yaml', '.yml', '.json'}:
            return parsed

    if not LINK_RE.search(text) and re.fullmatch(r'[A-Za-z0-9_+/=\-\s]+', stripped) and len(stripped) > 24:
        try:
            decoded = decode64(stripped)
            if LINK_RE.search(decoded):
                return parse_document(decoded, source + '.decoded.txt', default_protocol)
        except (ValueError, UnicodeError):
            pass
    for number, line in enumerate(text.splitlines(), 1):
        links = list(LINK_RE.finditer(line))
        if links:
            for match in links:
                link = match.group().rstrip(')]}\'`，。;')
                try:
                    u = urlsplit(link)
                    # Ordinary website links in prose are not proxy nodes.
                    if u.scheme.lower() in {'http', 'https'} and u.username is None and u.port is None:
                        continue
                    add(parse_link(link, source, number))
                except (ValueError, KeyError, TypeError, UnicodeError):
                    issue(number)
            continue
        candidate = line.strip().strip('`').lstrip('-* ').strip()
        if not candidate or candidate.startswith('#'):
            continue
        try:
            scheme = default_protocol
            parts = re.split(r'[,\t ]+', candidate)
            if parts[0].lower() in {'http', 'https', 'socks5', 'socks5h', 'socks4', 'socks4a'}:
                scheme, parts = parts[0].lower(), parts[1:]
            if len(parts) in {2, 4} and parts[1].isdigit():
                candidate = f'{parts[0]}:{parts[1]}'
                if len(parts) == 4:
                    candidate = f'{quote(parts[2], safe="")}:{quote(parts[3], safe="")}@{candidate}'
            elif '@' not in candidate:
                fields = re.match(r'^(\[[^]]+\]|[A-Za-z0-9_.-]+):(\d+)(?::([^:]*):(.*))?$', candidate)
                if not fields:
                    if re.match(r'^[\w.-]+:\d+', candidate):
                        issue(number)
                    continue
                host, port, user, password = fields.groups()
                candidate = f'{host}:{port}'
                if user is not None:
                    candidate = f'{quote(user, safe="")}:{quote(password, safe="")}@{candidate}'
            add(parse_link(scheme + '://' + candidate, source, number))
        except (ValueError, TypeError, KeyError):
            issue(number)
    return parsed


def read_document(data: bytes, filename: str, default_protocol='http') -> Parsed:
    if len(data) > MAX_BYTES:
        raise ValueError('单个文件不能超过 5 MB')
    if Path(filename).suffix.lower() == '.docx':
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                info = archive.getinfo('word/document.xml')
                if info.file_size > MAX_BYTES:
                    raise ValueError('解压后的文档过大')
                root = ET.fromstring(archive.read(info))
            ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
            text = '\n'.join(''.join(p.itertext()) for p in root.findall('.//w:p', ns))
        except (zipfile.BadZipFile, KeyError, ET.ParseError):
            raise ValueError('无法读取 DOCX 文档') from None
    else:
        for encoding in ('utf-8-sig', 'utf-16', 'gb18030'):
            try:
                text = data.decode(encoding)
                break
            except UnicodeError:
                continue
        else:
            raise ValueError('文档编码无法识别，请另存为 UTF-8 文本')
    return parse_document(text, Path(filename).name, default_protocol)


@dataclass
class Check:
    target: str
    ok: bool
    http_status: int = 0
    latency_ms: float = 0
    exit_ip: str = ''
    error: str = ''


@dataclass
class Result:
    node: Node
    checks: list[Check]
    status: str
    note: str = ''

    @property
    def usable(self):
        return self.status == 'usable'

    def public(self):
        successful = [c for c in self.checks if c.ok]
        return {'id': self.node.key[:12], 'endpoint': self.node.label,
                'protocol': self.node.protocol, 'status': self.status,
                'usable': self.usable, 'passed': len(successful), 'total': len(self.checks),
                'latency_ms': round(statistics.median(c.latency_ms for c in successful), 1) if successful else None,
                'exit_ips': sorted({c.exit_ip for c in successful if c.exit_ip}),
                'source': Path(self.node.source).name, 'line': self.node.line,
                'note': self.note, 'checks': [asdict(c) for c in self.checks]}


def classify(node, checks, minimum, note=''):
    count = sum(c.ok for c in checks)
    return Result(node, checks, 'usable' if count >= minimum else 'partial' if count else 'failed', note)


def extract_ip(body):
    try:
        value = json.loads(body)
        candidates = [value.get('ip', ''), value.get('origin', '')] if isinstance(value, dict) else []
    except (ValueError, TypeError):
        candidates = []
    candidates.extend(re.findall(r'^ip=(.+)$', body, re.M))
    candidates.append(body.strip())
    for value in candidates:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except (ValueError, AttributeError):
            pass
    return ''


def curl_quote(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\r', '\\r').replace('\n', '\\n') + '"'


def curl_check(proxy, target, timeout=12, interface='', curl='curl', ca_bundle=''):
    # Credentials go through stdin, never through the process command line.
    settings = {'proxy': proxy, 'noproxy': '', 'url': target, 'max-time': timeout,
                'connect-timeout': min(timeout, 6), 'max-filesize': 65536,
                'write-out': '\\nNODECHECK_META:%{http_code} %{time_total} %{http_connect}',
                'proto': '=http,https', 'user-agent': 'NodeCheck/1.0'}
    if interface:
        settings['interface'] = interface
    if ca_bundle:
        settings['cacert'] = ca_bundle
    config = '\n'.join(f'{k} = {curl_quote(v)}' for k, v in settings.items())
    # curl config must receive a literal backslash-n for write-out to interpret.
    config = config.replace('\\\\nNODECHECK_META:', '\\nNODECHECK_META:')
    config += '\nsilent\nshow-error\n'
    env = {k: v for k, v in os.environ.items() if k.lower() not in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}}
    try:
        proc = subprocess.run([curl, '-q', '--config', '-'], input=config.encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 3,
                              env=env, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        body, _, meta = proc.stdout.rpartition(b'\nNODECHECK_META:')
        fields = meta.decode('ascii', 'replace').split()
        status = int(fields[0]) if len(fields) == 3 else 0
        elapsed = float(fields[1]) * 1000 if len(fields) == 3 else 0
        connect_status = int(fields[2]) if len(fields) == 3 else 0
        errors = {5: '代理域名解析失败', 6: '目标域名解析失败', 7: '连接失败',
                  28: '连接或请求超时', 35: 'TLS 握手失败', 47: '重定向过多',
                  60: '目标 TLS 证书校验失败', 63: '响应超过大小限制',
                  67: '代理账号认证失败', 97: '代理握手或认证失败', 45: '出口网卡绑定失败',
                  56: '代理连接中断或拒绝隧道'}
        error = ''
        if proc.returncode:
            error = errors.get(proc.returncode, f'curl 错误 {proc.returncode}')
            if connect_status == 407 or b'407' in proc.stderr:
                error = '代理账号认证失败（407）'
            elif connect_status >= 400:
                error = f'代理拒绝 CONNECT 隧道（HTTP {connect_status}）'
        elif not 200 <= status < 300:
            error = f'HTTP {status}（仅接受 2xx）'
        # IP endpoints must actually return an IP, not a captive portal's 200 page.
        ip = extract_ip(body.decode('utf-8', 'replace')) if not error else ''
        if not error and urlsplit(target).hostname in {'api.ipify.org', 'www.cloudflare.com'} and not ip:
            error = '出口 IP 检测响应无效'
        return Check(target, not bool(error), status, elapsed, ip, error)
    except subprocess.TimeoutExpired:
        return Check(target, False, error='进程超时')


@contextlib.contextmanager
def mihomo_proxy(node, executable, interface=''):
    if not executable:
        raise ValueError('此协议需要 Mihomo：请使用 --mihomo 指定内核路径')
    with tempfile.TemporaryDirectory(prefix='nodecheck-') as directory:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        password = secrets.token_urlsafe(24)
        cfg = copy.deepcopy(node.config)
        cfg['name'] = 'tested-node'
        config = {'mixed-port': port, 'bind-address': '127.0.0.1', 'allow-lan': False,
                  'authentication': ['probe:' + password], 'mode': 'rule', 'log-level': 'silent',
                  'ipv6': True, 'tun': {'enable': False}, 'dns': {'enable': False},
                  'proxies': [cfg], 'rules': ['MATCH,tested-node'], 'geo-auto-update': False}
        if interface:
            config['interface-name'] = interface
        path = Path(directory) / 'config.json'
        path.write_text(json.dumps(config), encoding='utf-8')
        if os.name != 'nt':
            path.chmod(0o600)
        with open(os.devnull, 'wb') as null:
            proc = subprocess.Popen([executable, '-d', directory, '-f', str(path)], stdout=null, stderr=null,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            try:
                deadline = time.monotonic() + 8
                while True:
                    if proc.poll() is not None:
                        raise ValueError('Mihomo 启动失败，请检查协议参数或内核版本')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.15):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise ValueError('Mihomo 启动超时') from None
                        time.sleep(.05)
                yield f'http://probe:{password}@127.0.0.1:{port}'
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


@dataclass
class Options:
    targets: tuple = DEFAULT_TARGETS
    timeout: float = 12
    workers: int = 4
    rounds: int = 1
    minimum: int = 2
    interface: str = ''
    core_interface: str = ''
    mihomo: str = ''
    curl: str = 'curl'
    ca_bundle: str = ''


def check_node(node, options, stop=None):
    checks = []
    try:
        direct = node.direct_url()
        manager = contextlib.nullcontext(direct) if direct else mihomo_proxy(node, options.mihomo, options.core_interface)
        with manager as proxy:
            for _ in range(options.rounds):
                for target in options.targets:
                    if stop and stop.is_set():
                        return Result(node, checks, 'cancelled', '测试已取消')
                    checks.append(curl_check(proxy, target, options.timeout,
                                             options.interface if direct else '', options.curl, options.ca_bundle))
        return classify(node, checks, options.minimum)
    except (ValueError, OSError) as e:
        # Only our controlled ValueErrors are safe to show; OS messages can contain paths.
        return Result(node, checks, 'unsupported' if not options.mihomo and not node.direct_url() else 'error',
                      str(e) if isinstance(e, ValueError) else '无法启动检测进程，请检查运行环境')


def run_checks(nodes, options, progress=None, stop=None):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=options.workers) as pool:
        pending = {pool.submit(check_node, node, options, stop): node for node in nodes}
        for future in concurrent.futures.as_completed(pending):
            result = future.result()
            results.append(result)
            if progress:
                progress(result, len(results), len(nodes))
    order = {node.key: i for i, node in enumerate(nodes)}
    return sorted(results, key=lambda r: order[r.node.key])


def export_files(results, issues, route_note='测试沿运行机器的当前网络路径进行；可用性不等于家宽归属。'):
    usable = [r for r in results if r.usable]
    records = [r.public() for r in results]
    out = io.StringIO(newline='')
    fields = ['id', 'endpoint', 'protocol', 'status', 'usable', 'passed', 'total', 'latency_ms', 'exit_ips', 'source', 'line', 'note', 'failures']
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for record in records:
        row = {k: record[k] for k in fields if k in record}
        row['exit_ips'] = ';'.join(record['exit_ips'])
        row['failures'] = ';'.join(c['error'] for c in record['checks'] if not c['ok'])
        # Prevent a filename or other user input becoming a spreadsheet formula.
        writer.writerow({k: "'" + v if isinstance(v, str) and v.startswith(('=', '+', '-', '@')) else v for k, v in row.items()})
    links = [r.node.share or r.node.direct_url() for r in usable]
    lines = [link for link in links if link]
    configs = []
    for i, r in enumerate(usable, 1):
        cfg = copy.deepcopy(r.node.config)
        cfg['name'] = f'usable-{i:04d}'
        configs.append(cfg)
    clash = {'proxies': configs}
    files = {'report.csv': out.getvalue().encode('utf-8-sig'),
             'report.json': json.dumps({'route_note': route_note, 'results': records, 'parse_issues': issues}, ensure_ascii=False, indent=2).encode(),
             'available.txt': ('\n'.join(lines) + ('\n' if lines else '')).encode(),
             'exit_ips.txt': ('\n'.join(sorted({ip for r in usable for ip in r.public()['exit_ips']})) + ('\n' if any(r.public()['exit_ips'] for r in usable) else '')).encode(),
             'NOTES.txt': (route_note + '\n可用节点的连接信息保存在 available.txt 和 clash.yaml/json 中，包含账号密码。\n'
                           'YAML 输入的复杂协议节点以 Clash 节点文件为准；报告不含账号密码。\n' + '\n'.join(issues)).encode()}
    if yaml:
        files['clash.yaml'] = yaml.safe_dump(clash, allow_unicode=True, sort_keys=False).encode()
    else:
        files['clash.json'] = json.dumps(clash, ensure_ascii=False, indent=2).encode()
    return files


def main():
    parser = argparse.ArgumentParser(description='识别混合代理节点文档，实际测试并导出可用节点。')
    parser.add_argument('files', nargs='+', type=Path)
    parser.add_argument('-o', '--output', type=Path, default=None)
    parser.add_argument('--timeout', type=float, default=12)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--rounds', type=int, default=1)
    parser.add_argument('--min-success', type=int, default=2)
    parser.add_argument('--target', action='append', help='自定义测试 URL，可重复；只接受 2xx')
    parser.add_argument('--interface', default='', help='curl 出口本地 IP 或网卡；Windows 建议使用本地 IP')
    parser.add_argument('--core-interface', default='', help='Mihomo 出口网卡名称')
    parser.add_argument('--mihomo', default=shutil.which('mihomo') or '')
    parser.add_argument('--default-protocol', choices=['http', 'socks5'], default='http', help='裸 IP:端口:账号:密码的协议')
    parser.add_argument('--parse-only', action='store_true', help='只识别数量及格式，不联网')
    args = parser.parse_args()
    targets = tuple(args.target or DEFAULT_TARGETS)
    if not 1 <= args.workers <= 32 or not 1 <= args.rounds <= 5 or not 1 <= args.timeout <= 60:
        parser.error('workers 需在 1–32、rounds 在 1–5、timeout 在 1–60 之间')
    if not 1 <= args.min_success <= len(targets) * args.rounds:
        parser.error('min-success 不能超过总检测次数')
    if any(urlsplit(t).scheme not in {'http', 'https'} or not urlsplit(t).hostname for t in targets):
        parser.error('target 必须是 http(s) URL')
    curl = shutil.which('curl.exe' if os.name == 'nt' else 'curl')
    if not curl and not args.parse_only:
        parser.error('未安装 curl')
    nodes, issues, seen = [], [], set()
    for path in args.files:
        try:
            if path.stat().st_size > MAX_BYTES:
                raise ValueError('文件超过 5 MB')
            parsed = read_document(path.read_bytes(), path.name, args.default_protocol)
        except (OSError, ValueError):
            print(f'无法读取文件：{path.name}，请检查格式、编码和大小。')
            return 2
        issues.extend(parsed.issues)
        for node in parsed.nodes:
            if node.key not in seen:
                seen.add(node.key)
                nodes.append(node)
    print(f'识别到 {len(nodes)} 个去重节点，{len(issues)} 条解析提示。')
    if args.parse_only:
        return 0 if nodes else 2
    if not nodes:
        return 2
    options = Options(targets, args.timeout, args.workers, args.rounds, args.min_success,
                      args.interface, args.core_interface, args.mihomo, curl)
    print('提示：当前 TUN / 路由仍可能影响结果；结果不证明家宽属性。')
    def progress(result, done, total):
        print(f'[{done}/{total}] {result.node.label}  {result.status}  '
              f'{sum(c.ok for c in result.checks)}/{len(result.checks)}', flush=True)
    results = run_checks(nodes, options, progress)
    folder = args.output or Path('results') / time.strftime('%Y%m%d-%H%M%S')
    folder.mkdir(parents=True, exist_ok=False, mode=0o700)
    for filename, content in export_files(results, issues).items():
        target = folder / filename
        target.write_bytes(content)
        if os.name != 'nt':
            target.chmod(0o600)
    usable = sum(r.usable for r in results)
    print(f'完成：{usable}/{len(results)} 可用，结果目录：{folder.resolve()}')
    return 0 if usable else 1


if __name__ == '__main__':
    raise SystemExit(main())

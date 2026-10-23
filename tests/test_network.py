"""Real sockets, TLS, HTTP CONNECT, credentials, and optional Mihomo integration."""
import base64
from datetime import datetime, timedelta, timezone
import http.server
import importlib.util
import ipaddress
import os
from pathlib import Path
import select
import shutil
import socket
import socketserver
import ssl
import tempfile
import threading
import unittest

import nodecheck as nc


class Origin(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = b'{"ip":"203.0.113.77"}'
        self.send_response(200 if self.path != '/blocked' else 403)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ConnectProxy(socketserver.StreamRequestHandler):
    def handle(self):
        first = self.rfile.readline(4096).decode()
        headers = {}
        while True:
            line = self.rfile.readline(4096)
            if line in {b'\r\n', b'\n', b''}:
                break
            name, _, value = line.decode().partition(':')
            headers[name.lower()] = value.strip()
        expected = 'Basic ' + base64.b64encode(b'alice:synthetic-password').decode()
        if headers.get('proxy-authorization') != expected:
            self.wfile.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="test"\r\nContent-Length: 0\r\n\r\n')
            self.wfile.flush()
            return
        method, target, _ = first.split()
        if method != 'CONNECT':
            return
        host, port = target.rsplit(':', 1)
        with socket.create_connection((host, int(port)), timeout=5) as upstream:
            self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            self.wfile.flush()
            while True:
                ready, _, _ = select.select([self.connection, upstream], [], [], 5)
                if not ready:
                    return
                for src in ready:
                    payload = src.recv(65536)
                    if not payload:
                        return
                    (upstream if src is self.connection else self.connection).sendall(payload)


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'Optional cryptography needed for TLS integration fixtures')
class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        cls.directory = tempfile.TemporaryDirectory(prefix='nodecheck-test-')
        root = Path(cls.directory.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1))
                .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
        cls.ca = root/'ca.pem'
        cls.ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keypath = root/'key.pem'
        keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cls.origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.ca, keypath)
        cls.origin.socket = context.wrap_socket(cls.origin.socket, server_side=True)
        cls.proxy = socketserver.ThreadingTCPServer(('127.0.0.1', 0), ConnectProxy)
        cls.proxy.daemon_threads = True
        cls.threads = []
        for server in (cls.origin, cls.proxy):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)
        cls.target = f'https://127.0.0.1:{cls.origin.server_port}/ip'
        cls.proxy_url = f'http://alice:synthetic-password@127.0.0.1:{cls.proxy.server_address[1]}'
        cls.curl = shutil.which('curl.exe' if os.name == 'nt' else 'curl')

    @classmethod
    def tearDownClass(cls):
        for server in (cls.origin, cls.proxy):
            server.shutdown()
            server.server_close()
        cls.directory.cleanup()

    def test_real_tls_connect_ip_and_authentication_failure(self):
        result = nc.curl_check(self.proxy_url, self.target, 4, curl=self.curl, ca_bundle=str(self.ca))
        self.assertTrue(result.ok, result)
        self.assertEqual(result.exit_ip, '203.0.113.77')
        bad = nc.curl_check(self.proxy_url.replace('synthetic-password', 'wrong'), self.target, 4, curl=self.curl, ca_bundle=str(self.ca))
        self.assertFalse(bad.ok)
        self.assertIn('407', bad.error)
        blocked = nc.curl_check(self.proxy_url, self.target.replace('/ip','/blocked'), 4, curl=self.curl, ca_bundle=str(self.ca))
        self.assertFalse(blocked.ok)
        self.assertEqual(blocked.http_status, 403)

    def test_optional_mihomo_core_forwarding_and_cleanup(self):
        executable = os.environ.get('MIHOMO_PATH', '')
        if not executable:
            self.skipTest('Set MIHOMO_PATH to exercise the real core')
        node = nc.parse_document(self.proxy_url).nodes[0]
        with nc.mihomo_proxy(node, executable) as local_proxy:
            result = nc.curl_check(local_proxy, self.target, 5, curl=self.curl, ca_bundle=str(self.ca))
            self.assertTrue(result.ok, result)
            port = nc.urlsplit(local_proxy).port
        with self.assertRaises(OSError):
            socket.create_connection(('127.0.0.1', port), timeout=.3)

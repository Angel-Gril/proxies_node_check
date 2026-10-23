import base64
import json
import tempfile
import unittest
from pathlib import Path

import nodecheck as nc


class ParsingTests(unittest.TestCase):
    def test_mixed_document_deduplicates_credentials_and_decodes_password(self):
        parsed = nc.parse_document(
            '说明 https://example.com/guide\n'
            'http://demo:p%40ss%3Aword@192.0.2.8:3128\n'
            'http://demo:p%40ss%3Aword@192.0.2.8:3128\n'
            '192.0.2.9:1080:alice:secret\n'
            'socks5://bob:secret@[2001:db8::1]:1080', 'mixed.txt')
        self.assertEqual(len(parsed.nodes), 3)
        self.assertEqual(parsed.nodes[0].config['password'], 'p@ss:word')
        self.assertEqual(parsed.nodes[1].protocol, 'http')
        self.assertEqual(parsed.nodes[2].protocol, 'socks5')
        self.assertNotIn('p@ss', parsed.nodes[0].label)

    def test_base64_subscription_and_vless_reality(self):
        link = ('vless://11111111-1111-4111-8111-111111111111@192.0.2.10:443'
                '?security=reality&sni=example.com&pbk=PUBLIC_KEY&sid=aa&fp=chrome#demo')
        text = base64.urlsafe_b64encode(link.encode()).decode().rstrip('=')
        parsed = nc.parse_document(text, 'subscription.txt')
        self.assertEqual(len(parsed.nodes), 1)
        cfg = parsed.nodes[0].config
        self.assertEqual(cfg['reality-opts']['public-key'], 'PUBLIC_KEY')
        self.assertEqual(cfg['servername'], 'example.com')

    def test_yaml_preserves_transport_options_without_running_document_settings(self):
        parsed = nc.parse_document('''mixed-port: 9999
external-controller: 0.0.0.0:9090
proxies:
  - name: demo
    type: vmess
    server: 192.0.2.3
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    network: ws
    ws-opts:
      path: /ws
      headers: {Host: example.com}
''', 'nodes.yaml')
        self.assertEqual(parsed.nodes[0].config['ws-opts']['path'], '/ws')
        self.assertNotIn('external-controller', parsed.nodes[0].config)

    def test_bad_node_report_never_contains_raw_credentials(self):
        parsed = nc.parse_document('http://private-user:private-password@192.0.2.2:99999', 'bad.txt')
        self.assertFalse(parsed.nodes)
        self.assertNotIn('private-password', str(parsed.issues))
        self.assertNotIn('private-user', str(parsed.issues))

    def test_ss_sip002_and_vmess(self):
        auth = base64.urlsafe_b64encode(b'aes-128-gcm:test-password').decode().rstrip('=')
        vmess = base64.b64encode(json.dumps({'v': '2', 'add': '192.0.2.11', 'port': '443',
            'id': '11111111-1111-4111-8111-111111111111', 'aid': '0', 'net': 'ws',
            'path': '/test', 'host': 'example.com', 'tls': 'tls'}).encode()).decode()
        parsed = nc.parse_document(f'ss://{auth}@192.0.2.12:443\nvmess://{vmess}', 'mixed.txt')
        self.assertEqual([n.protocol for n in parsed.nodes], ['ss', 'vmess'])
        self.assertEqual(parsed.nodes[1].config['ws-opts']['headers']['Host'], 'example.com')


class ResultTests(unittest.TestCase):
    def test_partial_checks_are_not_exported_as_usable(self):
        node = nc.parse_document('http://alice:secret@192.0.2.8:3128', 'test.txt').nodes[0]
        result = nc.classify(node, [nc.Check('https://example.com', True, 200, 12, '203.0.113.5'),
                                    nc.Check('https://example.net', False, 0, 0, error='timeout')], 2)
        self.assertEqual(result.status, 'partial')
        self.assertNotIn('secret', json.dumps(result.public(), ensure_ascii=False))
        files = nc.export_files([result], [])
        self.assertEqual(files['available.txt'], b'')
        self.assertEqual(files['exit_ips.txt'], b'')

    def test_success_exports_full_node_but_redacts_report(self):
        node = nc.parse_document('http://alice:secret@192.0.2.8:3128', 'test.txt').nodes[0]
        checks = [nc.Check('https://example.com', True, 200, 15, '203.0.113.5') for _ in range(2)]
        files = nc.export_files([nc.classify(node, checks, 2)], [])
        self.assertIn(b'alice:secret@', files['available.txt'])
        self.assertNotIn(b'secret', files['report.csv'])
        self.assertEqual(files['exit_ips.txt'].decode().strip(), '203.0.113.5')


if __name__ == '__main__':
    unittest.main()

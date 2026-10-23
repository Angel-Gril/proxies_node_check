import os
from pathlib import Path
import shutil
import subprocess
import unittest


DEPLOY = Path(__file__).resolve().parents[1] / 'deploy'
SHELL = shutil.which('sh')
if not SHELL and os.name == 'nt':
    git_bash = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/bin/bash.exe'
    if git_bash.is_file():
        SHELL = str(git_bash)


class DeploymentTests(unittest.TestCase):
    def test_nginx_template_uses_deployment_domain(self):
        template = (DEPLOY / 'nginx.conf').read_text(encoding='utf-8')
        self.assertIn('server_name __NODECHECK_DOMAIN__;', template)
        self.assertIn('/live/__NODECHECK_DOMAIN__/fullchain.pem;', template)

    @unittest.skipUnless(SHELL, 'POSIX shell required for deployment checks')
    def test_custom_domain_rendering_preserves_runtime_variables(self):
        for domain in ('check.example.com', 'second.example.net'):
            with self.subTest(domain=domain):
                env = dict(os.environ, NODECHECK_DOMAIN=domain)
                result = subprocess.run(
                    [SHELL, '-c', 'set -eu; NODECHECK_DEPLOY_DIR="$1"; . "$1/common.sh"; render_nginx_config; render_renewal_hook',
                     'nodecheck-deploy-test', DEPLOY.as_posix()],
                    env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'server_name {domain};', result.stdout)
                self.assertIn(f'/live/{domain}/fullchain.pem;', result.stdout)
                self.assertIn(f'/live/{domain}"', result.stdout)
                self.assertIn('$host$request_uri', result.stdout)
                self.assertIn('${RENEWED_LINEAGE:-}', result.stdout)
                self.assertNotIn('__NODECHECK_DOMAIN__', result.stdout)

    @unittest.skipUnless(SHELL, 'POSIX shell required for deployment checks')
    def test_invalid_domains_stop_deployment_before_external_actions(self):
        for domain in ('', 'https://check.example.com', 'check.example.com:443',
                       'check.example.com/path', 'check.example.com; touch /tmp/unwanted',
                       'check.example.com\ninjected.example.org', '-bad.example.com',
                       'a' * 64 + '.example.com', '127.0.0.1'):
            for script in ('prepare.sh', 'install.sh', 'finalize.sh'):
                with self.subTest(domain=domain, script=script):
                    result = subprocess.run([SHELL, (DEPLOY / script).as_posix()],
                                            env=dict(os.environ, NODECHECK_DOMAIN=domain),
                                            capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('NODECHECK_DOMAIN', result.stderr)


if __name__ == '__main__':
    unittest.main()

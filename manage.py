"""Credential setup and local runner. Server deployment uses the same env file."""
import argparse
import getpass
import os
from pathlib import Path
import secrets
import subprocess
from werkzeug.security import generate_password_hash


def load_env(path):
    for line in path.read_text(encoding='utf-8').splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            os.environ[key] = value.strip('"')


def main():
    parser = argparse.ArgumentParser(description='检测网站的账号配置与本地启动')
    parser.add_argument('command', choices=['setup', 'serve'])
    parser.add_argument('--env', type=Path, default=Path('.private/app.env'))
    parser.add_argument('--port', type=int, default=18765)
    args = parser.parse_args()
    if args.command == 'setup':
        user = input('登录用户名：').strip()
        if not user or len(user) > 128 or any(c in user for c in '\r\n"\\'):
            parser.error('用户名不符合要求')
        password = getpass.getpass('登录密码（至少 12 位）：')
        if len(password) < 12:
            parser.error('请使用至少 12 位密码')
        if password != getpass.getpass('再次输入密码：'):
            parser.error('两次密码不一致')
        args.env.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if args.env.exists():
            parser.error('配置已存在；如需更新，请先手动备份并移走原文件')
        value = f'LOGIN_USER={user}\nPASSWORD_HASH={generate_password_hash(password)}\nAPP_SECRET={secrets.token_urlsafe(48)}\nCOOKIE_SECURE=true\n'
        fd = os.open(args.env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(value)
        print('已保存用户名、密码哈希和会话密钥。')
        return
    if not args.env.is_file():
        parser.error('请先运行 python manage.py setup')
    load_env(args.env)
    os.environ['COOKIE_SECURE'] = 'false'
    from webapp import create_app
    from werkzeug.serving import make_server
    app = create_app()
    print(f'本地地址：http://127.0.0.1:{args.port} （服务器请使用 Gunicorn + HTTPS）')
    with make_server('127.0.0.1', args.port, app, threaded=True) as server:
        try:
            server.serve_forever()
        finally:
            app.extensions['nodecheck_store'].close()


if __name__ == '__main__':
    main()

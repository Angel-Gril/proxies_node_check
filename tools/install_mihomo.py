"""Download a pinned official Mihomo artifact and verify GitHub's SHA-256 digest."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import urllib.request
import zipfile

VERSION = 'v1.19.33'


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'nodecheck-installer', 'Accept': 'application/vnd.github+json' if 'api.github.com' in url else '*/*'})
    with urllib.request.urlopen(req, timeout=90) as response:
        return response.read(90 * 1024 * 1024)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    system = {'Windows': 'windows', 'Linux': 'linux'}.get(platform.system())
    arch = {'AMD64': 'amd64-compatible', 'x86_64': 'amd64-compatible', 'aarch64': 'arm64', 'ARM64': 'arm64'}.get(platform.machine())
    if not system or not arch:
        parser.error('请从 https://github.com/MetaCubeX/mihomo/releases 手动下载适合此系统的内核')
    extension = '.zip' if system == 'windows' else '.gz'
    name = f'mihomo-{system}-{arch}-{VERSION}{extension}'
    release = json.loads(fetch('https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/' + VERSION))
    asset = next(a for a in release['assets'] if a['name'] == name)
    digest = asset.get('digest', '')
    if not digest.startswith('sha256:'):
        parser.error('官方发布没有提供 SHA-256 摘要，已停止安装')
    payload = fetch(asset['browser_download_url'])
    if 'sha256:' + hashlib.sha256(payload).hexdigest() != digest:
        parser.error('下载文件的 SHA-256 不匹配')
    if system == 'windows':
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            binary_name = next(n for n in archive.namelist() if n.endswith('.exe'))
            binary = archive.read(binary_name)
    else:
        binary = gzip.decompress(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as stream:
        stream.write(binary)
    if os.name != 'nt':
        args.output.chmod(0o755)
    print(f'Installed {VERSION}; official archive {digest}; path: {args.output.resolve()}')


if __name__ == '__main__':
    main()

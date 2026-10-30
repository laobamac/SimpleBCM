#!/usr/bin/env python3
#
#  publish.py
#  SimpleBCM
#
#  Created by laobamac on 2026/9/28.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from package import VERSION, package_name, variants


def release_body(repository, sha):
    source = f'https://github.com/{repository}/blob/{sha}'
    return f'''支持 macOS Sequoia 15 和 macOS Tahoe 26，通过 OpenCore 注入恢复 Broadcom Wi-Fi 驱动，无需修改系统卷。

- SimpleBCM 同时支持两个系统；相同构建类型的二进制完全一致，系统包仅区分配套驱动和配置。
- 每个系统提供 DEBUG 和 RELEASE 包，日常使用请选择对应系统的 RELEASE 包。
- BCM943224PCIEBT2 已通过用户基本使用测试。安装方法与支持范围见 [README]({source}/README.md)。

<details>
<summary>English</summary>

Supports macOS Sequoia 15 and macOS Tahoe 26, restoring Broadcom Wi-Fi drivers through OpenCore injection without modifying the system volume.

- SimpleBCM supports both systems. Binaries of the same build type are identical; OS-specific packages differ only in companion drivers and configuration.
- DEBUG and RELEASE packages are available for each system. Choose the RELEASE package for your macOS version for everyday use.
- Basic operation with BCM943224PCIEBT2 has been confirmed by the user. See the [README]({source}/README.en.md) for installation and supported configurations.

</details>'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--channel', choices=('pre', 'rel'), required=True)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    repository = os.environ['GITHUB_REPOSITORY']
    sha = os.environ['GITHUB_SHA'].lower()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise SystemExit('Invalid repository name')
    if not re.fullmatch(r'[0-9a-fA-F]{40}', sha):
        raise SystemExit('Invalid commit SHA')
    body = release_body(repository, sha)
    files = []
    for system, configuration in variants():
        name = package_name(system, configuration, args.channel, sha)
        archive = root / 'dist' / (name + '.zip')
        checksum = archive.with_name(archive.name + '.sha256')
        if not archive.is_file() or not checksum.is_file():
            raise SystemExit(f'Release archive or checksum is missing: {name}')
        if checksum.read_text().split() != [hashlib.sha256(archive.read_bytes()).hexdigest(), archive.name]:
            raise SystemExit(f'Release archive checksum differs: {name}')
        files.append(archive)
    release = None
    if args.channel == 'rel':
        release = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()).get('release', {})
        tag = release.get('tag_name', '')
        if release.get('prerelease') or release.get('draft') or tag not in (VERSION, f'v{VERSION}'):
            raise SystemExit(f'Formal release tag must be {VERSION} or v{VERSION}')
    else:
        tag = f'v{VERSION}-alpha'
    if args.dry_run:
        print(json.dumps({'repository': repository, 'tag': tag, 'channel': args.channel,
                          'body': body, 'assets': [p.name for p in files]}, indent=2))
        return
    token = os.environ['GH_TOKEN']
    api = os.environ.get('GITHUB_API_URL', 'https://api.github.com')
    base = f'/repos/{repository}'

    def request(method, path, data=None, missing=False):
        body = None if data is None else json.dumps(data).encode()
        headers = {'Accept': 'application/vnd.github+json', 'Authorization': f'Bearer {token}',
                   'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'}
        query = urllib.request.Request(api + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(query, timeout=60) as response:
                text = response.read()
                return json.loads(text) if text else None
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing:
                return None
            raise SystemExit(f'GitHub {method} {path} failed: HTTP {error.code}') from None

    if release is not None:
        current = request('GET', base + '/releases/' + str(release['id']))
        if current['tag_name'] != tag or current['prerelease'] or current['draft']:
            raise SystemExit('Release state changed during the build')
        request('PATCH', base + '/releases/' + str(current['id']), {'body': body})
    else:
        encoded = urllib.parse.quote(tag, safe='')
        current = request('GET', base + '/releases/tags/' + encoded, missing=True)
        if current and (not current['prerelease'] or current['draft']):
            raise SystemExit('Alpha tag is already used by a formal or draft release')
        ref = request('GET', base + '/git/ref/tags/' + encoded, missing=True)
        if ref:
            request('PATCH', base + '/git/refs/tags/' + encoded, {'sha': sha, 'force': True})
        else:
            request('POST', base + '/git/refs', {'ref': 'refs/tags/' + tag, 'sha': sha})
        values = {'tag_name': tag, 'target_commitish': sha, 'name': tag, 'body': body,
                  'draft': False, 'prerelease': True, 'make_latest': 'false'}
        if current:
            current = request('PATCH', base + '/releases/' + str(current['id']), values)
        else:
            current = request('POST', base + '/releases', values)
    subprocess.run(['gh', 'release', 'upload', tag, *(str(p) for p in files), '--repo', repository, '--clobber'], check=True)
    if args.channel == 'pre':
        keep = {p.name for p in files}
        # Only replace stale assets on this version's managed Alpha release.
        page = 1
        stale = []
        while True:
            assets = request('GET', base + f'/releases/{current["id"]}/assets?per_page=100&page={page}')
            stale.extend(asset['id'] for asset in assets if asset['name'] not in keep)
            if len(assets) < 100:
                break
            page += 1
        for identifier in stale:
            request('DELETE', base + '/releases/assets/' + str(identifier))
    print(f'Published {tag}: ' + ', '.join(p.name for p in files))


if __name__ == '__main__':
    main()

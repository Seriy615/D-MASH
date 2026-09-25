#!/usr/bin/env python3
"""Compare every deployed PWA/backend source file with an immutable Git commit.

Read-only. Runtime state, private keys, databases and logs are never read.
Run separately from browser/SW and live-service acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REMOTE = r'''
import hashlib, json, pathlib, sys
manifest = json.load(sys.stdin)
missing, changed = [], []
for row in manifest:
    path = pathlib.Path(row['path'])
    if not path.is_file():
        missing.append(row['label'])
    elif hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
        changed.append(row['label'])
print(json.dumps({'checked': len(manifest), 'missing': missing, 'changed': changed}))
sys.exit(int(bool(missing or changed)))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sha', help='full pushed commit SHA')
    parser.add_argument('--host', default='ems-vps')
    parser.add_argument('--pwa-root', default='/srv/messenger.d-mash.ru/public_html/not_messenger')
    parser.add_argument('--node-root', default='/opt/dmash-node/backend')
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.sha):
        parser.error('full 40-character lowercase Git SHA required')
    manifest = []
    for source, destination in [('D-MASH PWA/not_messenger', args.pwa_root),
                                ('D-MASH/client/backend', args.node_root)]:
        paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', '-z', args.sha, '--', source], cwd=ROOT).decode().split('\0')
        for name in filter(None, paths):
            # Source scopes must never grow to include runtime secret files.
            if any(part in {'..', '.git'} for part in Path(name).parts) or re.search(r'(\.key(?:\.|$)|\.basencrh$|\.db(?:-|$)|(?:^|/)\.env(?:\.|$))', name):
                raise RuntimeError('runtime secret path present in source manifest')
            content = subprocess.check_output(['git', 'show', f'{args.sha}:{name}'], cwd=ROOT)
            manifest.append({'label': name, 'path': destination + name[len(source):],
                             'sha256': hashlib.sha256(content).hexdigest()})
    result = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.host,
                             'python3 -c ' + shlex.quote(REMOTE)], input=json.dumps(manifest), text=True)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())

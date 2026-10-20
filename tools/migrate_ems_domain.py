#!/usr/bin/env python3
"""Migrate existing EMS endpoints without changing backend code or identities.

Review on EMS with --host proxy.d-mash.ru --site /etc/nginx/sites-available/FILE.
Default is read-only: validate an existing 443 TLS vhost and calculate changes.
After DNS A=85.198.64.183, HTTPS certificate verification and a protected
consistent SQLite/runtime identities+keys backup, use --apply.
Backups include the selected nginx file, node.env and turnserver.conf (0700/0600)
under /root/dmash-domain-backups. Only five exact API locations are managed; the
existing PWA, other vhosts, global coturn:3478, flags and secrets are preserved.
nginx -t precedes every reload. Restart dedicated coturn:3479 and dmash-node
using their existing units/code; this is not a backend upgrade. Verify pinned
Node auth, signed service descriptor, real TURN UDP/TCP relay and PWA afterwards.
Use --rollback BACKUP for explicit restoration, including a failed acceptance.
Never publish backups, configuration contents, credentials or runtime state.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PATHS = ('/mesh/v4', '/dmp-c/v3', '/dmash-client/v1', '/dmash-client/v3', '/signal/v1')
START = '    # BEGIN D-MASH canonical exact endpoints\n'
END = '    # END D-MASH canonical exact endpoints\n'


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or value != value.lower() or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', value):
        raise ValueError('Expected a lower-case DNS hostname, without scheme/path/port')
    return value


def replace_settings(text, values, separator='='):
    """Replace named settings only; preserve unrelated bytes and secret material."""
    remaining = dict(values)
    result = []
    seen = set()
    for line in text.splitlines(keepends=True):
        key = line.split(separator, 1)[0]
        if key in values:
            if key in seen:
                raise ValueError('Duplicate managed configuration key')
            seen.add(key)
            result.append(key + separator + remaining.pop(key) + '\n')
        else:
            result.append(line)
    if remaining and result and not result[-1].endswith('\n'):
        result[-1] += '\n'
    return ''.join(result) + ''.join(k + separator + v + '\n' for k, v in remaining.items())


def endpoint_block():
    return START + ''.join('    location = ' + route + ' {\n'
        '        proxy_pass http://127.0.0.1:18080' + ('/dmp-c/v3' if route in ('/dmash-client/v1', '/dmash-client/v3') else route) + ';\n'
        '        proxy_http_version 1.1;\n'
        '        proxy_set_header Host $host;\n'
        '        proxy_set_header X-Real-IP $remote_addr;\n'
        '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
        '        proxy_set_header X-Forwarded-Proto $scheme;\n'
        '        proxy_set_header Upgrade $http_upgrade;\n'
        '        proxy_set_header Connection "upgrade";\n'
        '        proxy_read_timeout 330s;\n'
        '        proxy_buffering off;\n'
        '    }\n' for route in PATHS) + END


def nginx_site(text, host):
    # Reject ambiguous structure rather than risk modifying another server.
    tokens = list(re.finditer(r'#.*?$|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]|[^\s{}#"\']+', text, re.M))
    depth = 0
    start = None
    servers = []
    for i, token in enumerate(tokens):
        word = token.group()
        if word.startswith('#'):
            continue
        if word == '{':
            if depth == 0 and i and tokens[i-1].group() == 'server':
                start = token.end()
            depth += 1
        elif word == '}':
            depth -= 1
            if depth < 0:
                raise ValueError('Unbalanced nginx configuration')
            if depth == 0 and start is not None:
                body = text[start:token.start()]
                names = re.findall(r'^\s*server_name\s+([^;]+);', body, re.M)
                if any(host in row.split() for row in names) and re.search(r'^\s*listen\s+[^;]*\b443\b[^;]*\bssl\b', body, re.M):
                    servers.append((start, token.start(), body))
                start = None
    if depth or len(servers) != 1:
        raise ValueError('Require exactly one existing canonical hostname TLS 443 server')
    first, last, body = servers[0]
    if body.count(START) == 1 and body.count(END) == 1 and body[body.index(START):body.index(END)+len(END)] == endpoint_block():
        # Still validate unmanaged conflicts below before accepting unchanged.
        current = True
    else: current = False
    if not re.search(r'^\s*ssl_certificate\s+', body, re.M):
        raise ValueError('Canonical TLS certificate directive missing')
    if START in body or END in body:
        if body.count(START) != 1 or body.count(END) != 1:
            raise ValueError('Ambiguous managed endpoint markers')
        a, b = body.index(START), body.index(END) + len(END)
        if b <= a:
            raise ValueError('Invalid managed endpoint marker order')
        body = body[:a] + body[b:]
    for route in PATHS:
        if re.search(r'\blocation\s+(?:=\s+)?' + re.escape(route) + r'(?:\s|\{)', body):
            raise ValueError('Existing API location requires manual review')
    if current: return text
    return text[:first] + body.rstrip() + '\n' + endpoint_block() + text[last:]


def atomic_write(path, data, stat):
    fd, temporary = tempfile.mkstemp(prefix=path.name+'.', dir=path.parent)
    try:
        os.fchmod(fd, stat.st_mode & 0o777)
        os.fchown(fd, stat.st_uid, stat.st_gid)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(*args):
    # nginx -t errors may contain configuration secrets; keep subprocess output private.
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args[:2]) + '; inspect protected host logs')


def restore(backup):
    manifest = json.loads((backup/'manifest.json').read_text())
    for row in manifest:
        path = Path(row['path'])
        if path.is_symlink():
            raise ValueError('Refusing configuration symlink')
        class Metadata:
            st_mode, st_uid, st_gid = row['mode'], row['uid'], row['gid']
        atomic_write(path, (backup/row['backup']).read_bytes(), Metadata)
    command('nginx', '-t')
    command('systemctl', 'restart', 'dmash-sturn', 'dmash-node')
    command('systemctl', 'reload', 'nginx')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--host', type=hostname, default='proxy.d-mash.ru')
    parser.add_argument('--site', type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--rollback', type=Path)
    args = parser.parse_args()
    if args.rollback:
        if os.geteuid() or args.apply or args.site:
            parser.error('Root rollback accepts only --rollback BACKUP')
        restore(args.rollback.resolve(strict=True))
        print('Restored protected configuration backup')
        return
    if not args.site:
        parser.error('--site is required; select the existing canonical TLS vhost')
    files = [args.site, Path('/etc/dmash-sturn/node.env'), Path('/etc/dmash-sturn/turnserver.conf')]
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError('Require existing regular configuration files')
    original = [path.read_bytes() for path in files]
    if not re.search(r'^listening-port=3479$', original[2].decode(), re.M):
        raise ValueError('Dedicated TURN port 3479 required')
    settings = {'DMASH_SIGNALING_WSS': 'wss://' + args.host + '/signal/v1', 'DMASH_TURN_URLS': ','.join('turn:' + args.host + ':3479?transport=' + t for t in ('udp', 'tcp'))}
    updated = [nginx_site(original[0].decode(), args.host).encode(), replace_settings(original[1].decode(), settings).encode(), replace_settings(original[2].decode(), {'server-name': args.host}).encode()]
    changed = [i for i in range(len(files)) if original[i] != updated[i]]
    print('Validated canonical exact endpoints; changed file count:', len(changed))
    if not args.apply or not changed:
        return
    if os.geteuid():
        raise RuntimeError('Root required for --apply')
    command('nginx', '-t')
    backup = Path('/root/dmash-domain-backups') / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(backup.parent, 0o700)
    manifest = []
    for i, path in enumerate(files):
        stat = path.stat()
        destination = backup/str(i)
        destination.write_bytes(original[i])
        os.chmod(destination, 0o600)
        manifest.append({'path': str(path.resolve()), 'backup': str(i), 'mode': stat.st_mode, 'uid': stat.st_uid, 'gid': stat.st_gid})
    (backup/'manifest.json').write_text(json.dumps(manifest))
    os.chmod(backup/'manifest.json', 0o600)
    try:
        for i in changed:
            atomic_write(files[i], updated[i], files[i].stat())
        command('nginx', '-t')
        command('systemctl', 'restart', 'dmash-sturn', 'dmash-node')
        command('systemctl', 'reload', 'nginx')
    except Exception:
        restore(backup)
        raise
    print('Applied canonical endpoints; protected rollback backup:', backup)


if __name__ == '__main__':
    main()

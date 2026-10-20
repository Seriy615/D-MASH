#!/usr/bin/env python3
"""Reviewable ACME bootstrap for the explicitly selected EMS API hostname.

First run without --apply. Root then reviews the host DNS A=85.198.64.183,
empty AAAA, existing ACME account/webroot, and free target nginx conf.d filename.
Run --apply only after approval; other vhosts and backend code remain unchanged.
The HTTP server serves ACME files only; HTTPS serves four exact API paths only.
Next run migrate_ems_domain.py --host HOST --site SITE (read-only), review its
changed count, then --apply to change existing signaling/TURN endpoint settings.
Dedicated coturn port/realm/secret, Node identities and flags remain intact.
If ACME/bootstrap fails the new nginx file is removed and prior nginx reloaded.
For later rollback remove ONLY the generated file, nginx -t then reload nginx;
restore the migration's protected backup separately. Retain the issued cert.
"""
import argparse
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
from migrate_ems_domain import hostname, endpoint_block, command


def http_server(host, webroot):
    return ('server {\n    listen 80;\n    server_name '+host+';\n'
        '    location ^~ /.well-known/acme-challenge/ {\n'
        '        root '+str(webroot)+';\n        default_type text/plain;\n    }\n'
        '    location / { return 404; }\n}\n')


def tls_server(host):
    return ('server {\n    listen 443 ssl;\n    server_name '+host+';\n'
        '    ssl_certificate /etc/letsencrypt/live/'+host+'/fullchain.pem;\n'
        '    ssl_certificate_key /etc/letsencrypt/live/'+host+'/privkey.pem;\n'
        '    ssl_protocols TLSv1.2 TLSv1.3;\n'+endpoint_block()+
        '    location / { return 404; }\n}\n')


def put(path, value):
    fd, name = tempfile.mkstemp(prefix=path.name+'.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            os.fchmod(handle.fileno(), 0o644)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    parser=argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--host',type=hostname,default='proxy.d-mash.ru')
    parser.add_argument('--site',type=Path,default=Path('/etc/nginx/conf.d/dmash-proxy-api.conf'))
    parser.add_argument('--webroot',type=Path,default=Path('/var/lib/letsencrypt'))
    parser.add_argument('--acme-account',help='Optional existing account ID; otherwise require exactly one account')
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    if args.acme_account and not re.fullmatch('[a-f0-9]{32}',args.acme_account):
        parser.error('Existing ACME account ID must be 32 lowercase hex digits')
    if not re.fullmatch('/[A-Za-z0-9_./-]+',str(args.webroot)) or '..' in args.webroot.parts:
        parser.error('Webroot requires a safe absolute path')
    if args.site.parent != Path('/etc/nginx/conf.d') or not re.fullmatch(r'[A-Za-z0-9_-]+\.conf',args.site.name):
        parser.error('Use a dedicated regular file under /etc/nginx/conf.d')
    final=http_server(args.host,args.webroot)+tls_server(args.host)
    if args.site.exists() or args.site.is_symlink():
        if not args.site.is_symlink() and args.site.read_text()==final:
            print('Canonical API vhost already configured; no changes')
            return
        raise RuntimeError('Target nginx file already exists; preserve and review it manually')
    print('Plan: isolated HTTP ACME vhost, certbot webroot certonly using existing account, exact API TLS vhost')
    if not args.apply:
        return
    if os.geteuid():
        raise RuntimeError('Root required')
    ipv4={x[4][0] for x in socket.getaddrinfo(args.host,80,socket.AF_INET)}
    try:
        ipv6=socket.getaddrinfo(args.host,80,socket.AF_INET6)
    except socket.gaierror as error:
        if error.errno not in (socket.EAI_NONAME,socket.EAI_NODATA):
            raise
        ipv6=[]
    if ipv4!={'85.198.64.183'} or ipv6:
        raise RuntimeError('Expected only EMS IPv4 and no IPv6 DNS address')
    active=subprocess.run(['nginx','-T'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout.decode()
    if any(args.host in row.split() for row in re.findall(r'\bserver_name\s+([^;]+);',active)):
        raise RuntimeError('Canonical hostname already configured elsewhere; review first')
    accounts=Path('/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory')
    ids=[p.name for p in accounts.iterdir() if p.is_dir() and re.fullmatch('[a-f0-9]{32}',p.name)]
    if args.acme_account:
        if args.acme_account not in ids:raise RuntimeError('Existing production ACME account not found')
    elif len(ids)==1:args.acme_account=ids[0]
    else:raise RuntimeError('Require exactly one existing ACME account or explicit --acme-account')
    if not args.webroot.is_dir():
        raise RuntimeError('Existing ACME webroot required')
    command('nginx','-t')
    import datetime, json
    backup=Path('/root/dmash-domain-backups')/('tls-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
    backup.mkdir(parents=True,mode=0o700);os.chmod(backup.parent,0o700)
    for name,data in [('nginx-before.txt',active),('manifest.json',json.dumps({'new_site':str(args.site),'previously_absent':True,'host':args.host}))]:
        (backup/name).write_text(data);os.chmod(backup/name,0o600)
    try:
        put(args.site,http_server(args.host,args.webroot))
        command('nginx','-t')
        command('systemctl','reload','nginx')
        command('certbot','certonly','--webroot','-w',str(args.webroot),'-d',args.host,'--cert-name',args.host,'--account',args.acme_account,'--non-interactive')
        put(args.site,final)
        command('nginx','-t')
        command('systemctl','reload','nginx')
    except Exception:
        args.site.unlink(missing_ok=True)
        command('nginx','-t')
        command('systemctl','reload','nginx')
        raise
    print('Canonical TLS API vhost configured; protected backup:',backup)


if __name__=='__main__':
    main()

#!/usr/bin/env python3
"""Configure the dedicated EMS S-TURN relay after deploying compatible code.

Run as root on EMS. Secrets are generated/stored only on that host and are never
printed. Existing global coturn/static users are preserved on port 3478.
"""
import base64
import datetime
import os
from pathlib import Path
import secrets
import shutil
import subprocess

ROOT=Path('/etc/dmash-sturn')
SITE=Path('/etc/nginx/sites-available/d-mash-ems-staging-tls')
DROP=Path('/etc/systemd/system/dmash-node.service.d/50-sturn.conf')
SERVICE=Path('/etc/systemd/system/dmash-sturn.service')
SNAPSHOTS=[]
TURN_WAS_ACTIVE=False
TURN_WAS_ENABLED=False

def write(path,text,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.is_symlink():raise RuntimeError('Refusing symlink configuration')
    temporary=path.with_name(path.name+'.new')
    with os.fdopen(os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode),'w') as handle:
        handle.write(text);handle.flush();os.fsync(handle.fileno())
    os.chmod(temporary,mode);os.replace(temporary,path)

def main():
    global TURN_WAS_ACTIVE,TURN_WAS_ENABLED
    if os.geteuid()!=0:raise RuntimeError('Root required')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup=Path('/root/dmash-sturn-backups')/stamp;backup.mkdir(parents=True,mode=0o700)
    for index,path in enumerate([SITE,DROP,SERVICE,ROOT/'turnserver.conf',ROOT/'node.env']):
        SNAPSHOTS.append((path,path.read_bytes() if path.exists() else None,path.stat() if path.exists() else None))
        if path.exists():shutil.copy2(path,backup/(str(index)+'-'+path.name))
    TURN_WAS_ACTIVE=subprocess.run(['systemctl','is-active','--quiet','dmash-sturn']).returncode==0
    TURN_WAS_ENABLED=subprocess.run(['systemctl','is-enabled','--quiet','dmash-sturn']).returncode==0
    ROOT.mkdir(mode=0o750,exist_ok=True)
    secret_path=ROOT/'rest.secret'
    if secret_path.exists():
        if secret_path.is_symlink():raise RuntimeError('Refusing secret symlink')
        secret=secret_path.read_text().strip()
        if len(secret)!=64 or any(c not in '0123456789abcdef' for c in secret):raise RuntimeError('Existing secret material invalid; not replaced')
    else:
        secret=secrets.token_hex(32);write(secret_path,secret+'\n')
    config='\n'.join([
        'listening-port=3479','listening-ip=0.0.0.0','relay-ip=85.198.64.183','external-ip=85.198.64.183',
        'realm=stage-api-ems.d-mash.ru','server-name=stage-api-ems.d-mash.ru',
        'use-auth-secret','static-auth-secret='+secret,'fingerprint','stale-nonce=600',
        'min-port=55000','max-port=55999','user-quota=8','total-quota=128',
        'max-bps=3000000','bps-capacity=64000000','relay-threads=2',
        'no-tls','no-dtls','no-cli','no-loopback-peers','no-multicast-peers',
        'no-stdout-log','syslog','userdb=/var/lib/dmash-sturn/turndb','pidfile=/run/dmash-sturn/turnserver.pid',''])
    write(ROOT/'turnserver.conf',config,0o640)
    shutil.chown(ROOT,group='turnserver');shutil.chown(ROOT/'turnserver.conf',group='turnserver')
    write(ROOT/'node.env','\n'.join([
        'DMASH_CAN_S_TURN=1','DMASH_SIGNALING_WSS=wss://stage-api-ems.d-mash.ru/signal/v1',
        'DMASH_TURN_URLS=turn:stage-api-ems.d-mash.ru:3479?transport=udp,turn:stage-api-ems.d-mash.ru:3479?transport=tcp',
        'DMASH_TURN_SHARED_SECRET_B64='+base64.b64encode(secret.encode()).decode(),''
    ]))
    write(SERVICE,'''[Unit]
Description=D-MASH ephemeral TURN relay
After=network-online.target
Wants=network-online.target
[Service]
User=turnserver
Group=turnserver
Type=simple
ExecStart=/usr/bin/turnserver -c /etc/dmash-sturn/turnserver.conf
Restart=on-failure
RestartSec=3
RuntimeDirectory=dmash-sturn
StateDirectory=dmash-sturn
StateDirectoryMode=0700
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
LimitNOFILE=8192
[Install]
WantedBy=multi-user.target
''',0o644)
    write(DROP,'[Service]\nEnvironmentFile=/etc/dmash-sturn/node.env\n',0o644)
    site=SITE.read_text()
    if 'location = /signal/v1' not in site:
        marker='    location = /mesh/v4 {'
        if marker not in site:raise RuntimeError('Known staging proxy anchor missing')
        site=site.replace(marker,'''    location = /signal/v1 {
        proxy_pass http://127.0.0.1:18080/signal/v1;
        include /etc/nginx/snippets/d-mash-ems-staging-proxy.conf;
        proxy_read_timeout 330s;
    }
'''+marker,1)
        write(SITE,site,0o644)
    subprocess.run(['nginx','-t'],check=True)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable','--now','dmash-sturn'],check=True)
    subprocess.run(['systemctl','restart','dmash-node'],check=True)
    subprocess.run(['systemctl','reload','nginx'],check=True)
    print('Configured dedicated S-TURN; backup:',backup)
    subprocess.run(['systemctl','is-active','dmash-sturn','dmash-node'],check=True)

def rollback():
    subprocess.run(['systemctl','stop','dmash-sturn'],check=False)
    if not TURN_WAS_ENABLED:subprocess.run(['systemctl','disable','dmash-sturn'],check=False)
    for path,data,metadata in SNAPSHOTS:
        if data is None:path.unlink(missing_ok=True)
        else:
            path.write_bytes(data);os.chmod(path,metadata.st_mode&0o777);os.chown(path,metadata.st_uid,metadata.st_gid)
    subprocess.run(['systemctl','daemon-reload'],check=False)
    if TURN_WAS_ACTIVE:subprocess.run(['systemctl','start','dmash-sturn'],check=False)
    subprocess.run(['systemctl','restart','dmash-node'],check=False)
    if subprocess.run(['nginx','-t']).returncode==0:subprocess.run(['systemctl','reload','nginx'],check=False)

if __name__=='__main__':
    try:main()
    except Exception:
        if SNAPSHOTS:rollback()
        raise

#!/usr/bin/env python3
"""Fetch exact Ubuntu build packages into an owned prefix; never apt install."""
import hashlib,json,os,pathlib,subprocess
recipe=pathlib.Path(__file__).resolve().parent.parent
cache=pathlib.Path(os.environ.get('DMASH_TOOLCHAIN_CACHE',str(pathlib.Path.home()/'.cache/dmash-native-20261020')))
archives=cache/'telegram-deb-packages';prefix=cache/'telegram-dependencies'
archives.mkdir(parents=True,exist_ok=True);prefix.mkdir(parents=True,exist_ok=True)
for row in json.loads((recipe/'LINUX_DEPENDENCIES.json').read_text())['packages']:
 path=archives/row['file']
 if not path.exists():subprocess.run(['apt-get','download',row['package']+'='+row['version']],cwd=archives,check=True)
 if hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:raise SystemExit('Package digest differs: '+path.name)
 subprocess.run(['dpkg-deb','-x',str(path),str(prefix)],check=True)
# Debian ships FindProtobuf-compatible libraries but no upstream CONFIG package.
config=prefix/'lib/cmake/protobuf';config.mkdir(parents=True,exist_ok=True)
(config/'protobufConfig.cmake').write_text('find_package(Protobuf MODULE REQUIRED)\nset(protobuf_FOUND TRUE)\n')

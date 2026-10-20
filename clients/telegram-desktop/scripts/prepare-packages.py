#!/usr/bin/env python3
"""Fetch exact Ubuntu build packages into an owned prefix; never apt install."""
import hashlib,json,os,pathlib,subprocess,tempfile,urllib.request
recipe=pathlib.Path(__file__).resolve().parent.parent
cache=pathlib.Path(os.environ.get('DMASH_TOOLCHAIN_CACHE',str(pathlib.Path.home()/'.cache/dmash-native-20261020')))
archives=cache/'telegram-deb-packages';prefix=cache/'telegram-dependencies'
archives.mkdir(parents=True,exist_ok=True);prefix.mkdir(parents=True,exist_ok=True)
for row in json.loads((recipe/'LINUX_DEPENDENCIES.json').read_text())['packages']:
 path=archives/row['file']
 if not path.exists():
  # Pool URLs remain reproducible when an apt mirror drops an older index entry.
  # Never select a different version or accept different archive contents.
  print('Fetch exact package:',row['package'],row['version'],row['url'],flush=True)
  temporary=None
  try:
   with tempfile.NamedTemporaryFile(dir=archives,prefix='.download-',delete=False) as output:
    temporary=pathlib.Path(output.name)
    with urllib.request.urlopen(row['url'],timeout=120) as response:
     while data:=response.read(1024*1024):output.write(data)
   if hashlib.sha256(temporary.read_bytes()).hexdigest()!=row['sha256']:raise SystemExit('Downloaded package digest differs: '+path.name)
   temporary.replace(path)
  finally:
   if temporary is not None:temporary.unlink(missing_ok=True)
 if hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:raise SystemExit('Package digest differs: '+path.name)
 subprocess.run(['dpkg-deb','-x',str(path),str(prefix)],check=True)
# Debian ships FindProtobuf-compatible libraries but no upstream CONFIG package.
config=prefix/'lib/cmake/protobuf';config.mkdir(parents=True,exist_ok=True)
(config/'protobufConfig.cmake').write_text('find_package(Protobuf MODULE REQUIRED)\nset(protobuf_FOUND TRUE)\n')

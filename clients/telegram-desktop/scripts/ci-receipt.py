#!/usr/bin/env python3
"""Validate cached dependency outputs, never project binaries or source snapshots."""
import hashlib,json,os,pathlib,subprocess,sys
recipe=pathlib.Path(__file__).resolve().parent.parent;cache=pathlib.Path(os.environ['DMASH_TOOLCHAIN_CACHE']);path=cache/'dependency-receipt.json'
inputs=['LINUX_DEPENDENCIES.json','SOURCE_DEPENDENCIES.json','scripts/ci-receipt.py','scripts/ci-qt.py','scripts/ci-prepare.sh','scripts/prepare-packages.py','scripts/prepare-source-dependencies.py','scripts/pkg-config']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
identity={'inputs':{p:sha(recipe/p) for p in inputs},'compiler':subprocess.check_output(['g++-13','--version'],text=True).splitlines()[0]}
required=['Qt/6.12.0/gcc_64/lib/libQt6Core.so.6','openssl-desktop/lib/libcrypto.so.3','telegram-dependencies/lib/libada.a','telegram-dependencies/lib/librnnoise.a','telegram-dependencies/lib/libtde2e.a','telegram-dependencies/lib/libtg_owt.a']
for name in required:
 if not (cache/name).is_file():raise SystemExit('Incomplete dependency outputs: '+name)
roots=['Qt/6.12.0/gcc_64','openssl-desktop','telegram-dependencies']
def inventory():
 out={}
 for root in roots:
  for p in sorted((cache/root).rglob('*')):
   if p.is_symlink():out[str(p.relative_to(cache))]={'link':os.readlink(p)}
   elif p.is_file():out[str(p.relative_to(cache))]=sha(p)
 return out
if sys.argv[1]=='write':
 identity['outputs']=inventory();path.write_text(json.dumps(identity,sort_keys=True)+'\n')
else:
 receipt=json.loads(path.read_text())
 if any(receipt.get(k)!=v for k,v in identity.items()) or receipt.get('outputs')!=inventory():raise SystemExit('Dependency cache receipt differs; no cached project state is accepted')
 print('PASS dependency input/compiler/output receipt')

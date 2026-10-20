#!/usr/bin/env python3
"""Create an Ubuntu24 developer bundle from actual built outputs and licenses."""
import hashlib,json,os,pathlib,re,shutil,subprocess
recipe=pathlib.Path(__file__).resolve().parent.parent;root=recipe.parents[1];cache=pathlib.Path(os.environ['DMASH_TOOLCHAIN_CACHE']);evidence=pathlib.Path(os.environ['DMASH_CI_EVIDENCE']);bundle=evidence/'bundle';qt=cache/'Qt/6.12.0/gcc_64'
(bundle/'bin').mkdir(parents=True,exist_ok=True);(bundle/'lib').mkdir();notices=bundle/'licenses';notices.mkdir()
inputs={'Telegram':cache/'build-telegram-desktop-fork/bin/Telegram','dmash-credential-host':cache/'build-credential-host/dmash-credential-host','dmash-node-host':cache/'build-native/dmash-node-host'}
for name,path in inputs.items():shutil.copy2(path,bundle/'bin'/name)
(bundle/'bin/qt.conf').write_text('[Paths]\nPrefix=..\nLibraries=lib\nPlugins=plugins\n')
plugins=[]
for group in ['platforms','imageformats','iconengines','platforminputcontexts','xcbglintegrations','tls']:
 for source in (qt/'plugins'/group).glob('*.so'):
  if group=='platforms' and source.name not in ['libqxcb.so','libqoffscreen.so']:continue
  dest=bundle/'plugins'/group/source.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest);plugins.append(dest)
source=qt/'plugins/sqldrivers/libqsqlite.so';dest=bundle/'plugins/sqldrivers'/source.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest);plugins.append(dest)
# Copy real ELF dependencies by their loader names; libc/loader remain the
# declared Ubuntu24 system baseline. A missing dependency is a packaging failure.
queue=list((bundle/'bin').glob('*'))+plugins;seen=set();origins={}
while queue:
 path=queue.pop()
 if path.name in seen or path.suffix=='.conf':continue
 seen.add(path.name);result=subprocess.run(['ldd',str(path)],capture_output=True,text=True)
 if result.returncode:raise RuntimeError('ldd failed: '+path.name)
 if 'not found' in result.stdout:raise RuntimeError('Missing runtime dependency for '+path.name+': '+result.stdout)
 for line in result.stdout.splitlines():
  match=re.search(r'^\s*(\S+) => (/\S+) ',line)
  if not match:continue
  name,original=match.groups()
  if name in ['libc.so.6','libpthread.so.0','libdl.so.2','librt.so.1','libm.so.6']:continue
  target=bundle/'lib'/name
  if not target.exists():shutil.copy2(pathlib.Path(original).resolve(),target);origins[name]=original;queue.append(target)
# Include exact project/core provenance and actual upstream/dependency notices.
shutil.copytree(root/'native/platforms/licenses',notices/'native-third-party')
for name in ['LICENSE','LICENSES.md']:shutil.copy2(root/name,notices/('D-MASH-'+name))
for path in ['PROVENANCE.json','README.md','vendor/wasm2c/LICENSE']:
 target=notices/'account'/path;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/'native/account'/path,target)
for path in ['LICENSE.upstream','LEGAL.upstream','LICENSES.md','UPSTREAM.json','SOURCE_DEPENDENCIES.json','LINUX_DEPENDENCIES.json']:
 shutil.copy2(recipe/path,notices/path)
for source_root in [cache/'telegram-desktop-fork',cache/'telegram-ada',cache/'telegram-rnnoise',cache/'telegram-tde2e',cache/'telegram-tg-owt',cache/'build/openssl-3.5.9',cache/'build/quickjs-2026-06-04']:
 for path in source_root.rglob('*'):
  if path.is_file() and any(term in path.name.lower() for term in ['license','copying','copyright','notice','authors','legal']) and '.git' not in path.parts:
   target=notices/'upstream'/source_root.name/path.relative_to(source_root);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
shutil.copytree(cache/'telegram-dependencies/usr/share/doc',notices/'ubuntu-dependencies',dirs_exist_ok=True)
launcher=bundle/'DMash';launcher.write_text('#!/bin/sh\nset -eu\napp=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexport LD_LIBRARY_PATH="$app/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"\nexec "$app/bin/Telegram" "$@"\n');launcher.chmod(0o755)
(bundle/'BUNDLE_SCOPE.txt').write_text('Actual Telegram Desktop fork + separate matching D-MASH credential/Node processes. Ubuntu24/glibc2.39 developer bundle; system display/GPU/audio services remain dependencies. No deployment, cross-platform, full messaging or UI acceptance is inferred from packaging.\n')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(evidence/'package.json').write_text(json.dumps({'sourceCommit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'files':{str(p.relative_to(bundle)):sha(p) for p in sorted(bundle.rglob('*')) if p.is_file()},'runtimeOrigins':origins,'scope':'Actual full app package; runtime acceptance recorded separately'},indent=2)+'\n')

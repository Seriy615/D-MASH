#!/usr/bin/env python3
"""Build pinned upstream dependencies sequentially in the owned cache."""
import hashlib,json,os,pathlib,subprocess,sys
verify_only="--verify-only" in sys.argv[1:]
sources_only="--sources-only" in sys.argv[1:]
recipe=pathlib.Path(__file__).resolve().parent.parent
cache=pathlib.Path(os.environ.get('DMASH_TOOLCHAIN_CACHE',str(pathlib.Path.home()/'.cache/dmash-native-20261020')))
prefix=cache/'telegram-dependencies';env=os.environ.copy()
env['PATH']=str(cache/'venv/bin')+':'+str(prefix/'usr/bin')+':'+env['PATH']
env['LD_LIBRARY_PATH']=str(prefix/'usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','')
env['PKG_CONFIG_SYSROOT_DIR']=str(prefix)
env['PKG_CONFIG_LIBDIR']=':'.join(str(prefix/x) for x in ['lib/pkgconfig','usr/lib/x86_64-linux-gnu/pkgconfig','usr/share/pkgconfig'])
def run(*args,cwd=None):subprocess.run(list(map(str,args)),cwd=cwd,env=env,check=True)
def git(path,*args):return subprocess.check_output(['git','-C',str(path),*args],text=True).strip()
for spec in json.loads((recipe/'SOURCE_DEPENDENCIES.json').read_text())['sources']:
 source=cache/('telegram-'+spec['name']);build=cache/('build-telegram-'+spec['name'])
 if not (source/'.git').exists():
  if verify_only:raise SystemExit('Dependency checkout missing: '+spec['name'])
  source.mkdir(parents=True,exist_ok=True);run('git','init',source);run('git','remote','add','origin',spec['repository'],cwd=source)
  run('git','fetch','--filter=blob:none','--depth','1','origin',spec['commit'],cwd=source);run('git','checkout','--detach',spec['commit'],cwd=source)
 if git(source,'rev-parse','HEAD')!=spec['commit'] or git(source,'status','--porcelain','--untracked-files=all'):raise SystemExit('Existing dependency differs: '+spec['name'])
 for module in spec['submodules']:
  path=source/module['path']
  if (path/'.git').exists() and (git(path,'rev-parse','HEAD')!=module['commit'] or git(path,'status','--porcelain','--untracked-files=all')):raise SystemExit('Existing dependency submodule differs: '+module['path'])
 if not verify_only:run('git','submodule','update','--init','--recursive','--depth','1','--jobs','1',cwd=source)
 raw=subprocess.check_output(['git','-C',str(source),'submodule','status','--recursive'],text=True)
 actual={line[1:].split()[1]:line[1:].split()[0] for line in raw.splitlines()}
 if actual!={m['path']:m['commit'] for m in spec['submodules']}:raise SystemExit('Dependency submodule inventory differs')
 for name,digest in spec['licenses'].items():
  if hashlib.sha256((source/name).read_bytes()).hexdigest()!=digest:raise SystemExit('Dependency license differs: '+name)
 if verify_only or sources_only:
  print('PASS pinned source/license/submodules: '+spec['name']);continue
 flags=['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_POLICY_VERSION_MINIMUM=3.5','-DCMAKE_CXX_FLAGS_RELEASE=-O1 -DNDEBUG','-DCMAKE_C_FLAGS_RELEASE=-O1 -DNDEBUG',f'-DCMAKE_INSTALL_PREFIX={prefix}',f'-DCMAKE_PREFIX_PATH={prefix};{prefix}/usr',f'-DPKG_CONFIG_EXECUTABLE={recipe}/scripts/pkg-config',f'-DOPENSSL_INCLUDE_DIR={cache}/openssl-desktop/include',f'-DOPENSSL_CRYPTO_LIBRARY={cache}/openssl-desktop/lib/libcrypto.so',f'-DOPENSSL_SSL_LIBRARY={cache}/openssl-desktop/lib/libssl.so']
 target=[]
 if spec['name']=='ada':flags+=['-DADA_TESTING=OFF','-DADA_BENCHMARKS=OFF','-DCMAKE_CXX_FLAGS_RELEASE=-O3 -DNDEBUG','-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG']
 if spec['name']=='tde2e':flags+=['-DTD_E2E_ONLY=ON'];target=['--target','tde2e']
 run('cmake','-S',source,'-B',build,'-G','Ninja',*flags)
 run('nice','-n','10','cmake','--build',build,*target,'-j'+os.environ.get('DMASH_BUILD_JOBS','1'))
 run('cmake','--install',build)
 if spec['name']=='rnnoise':
  pc=prefix/'lib/pkgconfig';pc.mkdir(exist_ok=True,parents=True)
  (pc/'rnnoise.pc').write_text('prefix=${pcfiledir}/../..\nlibdir=${prefix}/lib\nincludedir=${prefix}/include\nName: rnnoise\nDescription: Original desktop-app rnnoise\nVersion: 0.0.0\nLibs: -L${libdir} -lrnnoise -lm\nCflags: -I${includedir}\n')

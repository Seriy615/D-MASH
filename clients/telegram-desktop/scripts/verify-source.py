#!/usr/bin/env python3
"""Verify a pinned fork checkout without resetting or cleaning any file."""
import hashlib,json,pathlib,subprocess,sys
recipe,source=map(pathlib.Path,sys.argv[1:3]);mode=sys.argv[3]
pin=json.loads((recipe/'UPSTREAM.json').read_text())
def git(*args,cwd=source):return subprocess.check_output(['git','-C',str(cwd),*args])
def digest(data):return hashlib.sha256(data).hexdigest()
def require(ok,why):
 if not ok:raise SystemExit(why)
require(git('rev-parse','HEAD').decode().strip()==pin['commit'],'Wrong upstream revision')
require(digest((source/'LICENSE').read_bytes())==pin['licenseSha256'],'Upstream LICENSE differs')
require(digest((source/'LEGAL').read_bytes())==pin['legalSha256'],'Upstream LEGAL differs')
for patch in pin['patches']:require(digest((recipe/patch['path']).read_bytes())==patch['sha256'],'Patch differs: '+patch['path'])
modules={x['path']:x['commit'] for x in pin['submodules']}
# Compare the whole gitlink inventory, not just paths mentioned by the recipe.
actual_modules={}
for parent in ['',*modules]:
 owner=source/parent
 if parent and not (owner/'.git').exists():continue
 for entry in git('ls-tree','-r','HEAD',cwd=owner).decode().splitlines():
  meta,name=entry.split('\t',1);parts=meta.split()
  if parts[0]=='160000':actual_modules[(parent+'/' if parent else '')+name]=parts[2]
for name,revision in actual_modules.items():require(modules.get(name)==revision,'Unexpected gitlink: '+name)
if mode=='final':require(actual_modules==modules,'Incomplete gitlink inventory')
# Inspect each gitlink from its owning repository, including nested modules.
for name,revision in modules.items():
 parent=max((p for p in modules if name.startswith(p+'/')),key=len,default='')
 owner=source/parent;relative=name[len(parent)+1:] if parent else name
 if parent and not (owner/'.git').exists():continue
 row=git('ls-tree','HEAD','--',relative,cwd=owner).decode().strip().split()
 require(len(row)>=3 and row[0]=='160000' and row[2]==revision,'Gitlink mismatch: '+name)
 path=source/name
 if not (path/'.git').exists():
  require(mode=='preflight','Missing submodule: '+name);continue
 require(git('rev-parse','HEAD',cwd=path).decode().strip()==revision,'Existing submodule revision differs: '+name)
 require(not git('status','--porcelain','--untracked-files=all',cwd=path).strip(),'Dirty submodule: '+name)
expected=pin.get('patchedFiles',{})
status=git('status','--porcelain=v1','-z','--untracked-files=all').split(b'\0')
for entry in filter(None,status):
 name=entry[3:].decode()
 require(name in expected,'Unexpected checkout change: '+name)
 require(digest((source/name).read_bytes())==expected[name],'Changed fork file: '+name)
if mode=='final':
 for name,value in expected.items():require((source/name).is_file() and digest((source/name).read_bytes())==value,'Missing or changed patched file: '+name)

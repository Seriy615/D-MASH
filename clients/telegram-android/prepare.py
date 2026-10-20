#!/usr/bin/env python3
"""Create and verify the pinned GPL client fork; never reset an existing checkout."""
import argparse, hashlib, json, pathlib, subprocess
base = pathlib.Path(__file__).resolve().parent
manifest = json.loads((base / 'UPSTREAM.json').read_text())
parser = argparse.ArgumentParser(); parser.add_argument('checkout', type=pathlib.Path)
args = parser.parse_args(); checkout = args.checkout.resolve()
def run(*args, **kwargs): return subprocess.run(args, check=True, **kwargs)
def output(*args): return subprocess.check_output(args, text=True).strip()
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def refuse(message): raise SystemExit(message + '; refusing reset')
patches = []
for entry in manifest['patches']:
    path = base / entry['path']
    if digest(path) != entry['sha256']: refuse('Patch digest mismatch')
    patches.append(path)
series = hashlib.sha256(''.join(entry['sha256'] for entry in manifest['patches']).encode()).hexdigest()
if not checkout.exists():
    run('git', 'clone', '--filter=blob:none', '--no-checkout', '--depth=1', manifest['repository'], str(checkout))
    run('git', '-C', str(checkout), 'fetch', '--depth=1', '--no-tags', 'origin', manifest['commit'])
    run('git', '-C', str(checkout), 'checkout', '--detach', manifest['commit'])
# A receipt records application, never authority over the actual source tree.
if output('git','-C',str(checkout),'rev-parse','HEAD') != manifest['commit']: refuse('Existing HEAD is not the pinned upstream')
if digest(checkout / 'LICENSE') != manifest['licenseSha256']: refuse('Upstream license digest mismatch')
links = output('git','-C',str(checkout),'ls-tree','-r','HEAD')
actual_links = {line.split('\t',1)[1]:line.split()[2] for line in links.splitlines() if line.startswith('160000 ')}
if actual_links != manifest['submodules']: refuse('Upstream submodule pin map mismatch')
receipt = checkout / '.git' / 'dmash-patch-series'
if receipt.exists():
    if receipt.read_text().strip() != series: refuse('Existing fork has a different patch series')
else:
    dirty = output('git','-C',str(checkout),'status','--porcelain','--untracked-files=all','--ignore-submodules=all')
    if dirty: refuse('Unreceipted checkout has changes')
    for patch in patches:
        run('git', '-C', str(checkout), 'apply', '--check', str(patch))
        run('git', '-C', str(checkout), 'apply', str(patch))
# Verify the resulting patch projection, including new files that git diff omits.
for name, expected in manifest['patchedFiles'].items():
    path = checkout / name
    if expected is None:
        if path.exists(): refuse('Deleted patch file is present: ' + name)
    elif not path.is_file() or digest(path) != expected: refuse('Patched source digest mismatch: ' + name)
status = subprocess.check_output(['git','-C',str(checkout),'status','--porcelain=v1','-z','--untracked-files=all','--ignore-submodules=all'])
for entry in status.split(b'\0'):
    if not entry: continue
    if entry[:2] not in (b' M',b'M ',b'??',b' A',b'A ',b' D',b'D '): refuse('Unexpected source status')
    name = entry[3:].decode()
    if name not in manifest['patchedFiles']: refuse('Unexpected source change: ' + name)
# Existing submodules are validated BEFORE update: a stale receipt may never
# cause git submodule update to reset somebody's different checkout.
missing = []
for name, expected in manifest['submodules'].items():
    path = checkout / name
    if not (path / '.git').exists():
        if name in manifest['requiredSubmodules']: missing.append(name)
        continue
    if output('git','-C',str(path),'rev-parse','HEAD') != expected: refuse('Submodule HEAD mismatch: ' + name)
    if output('git','-C',str(path),'status','--porcelain','--untracked-files=all'): refuse('Submodule contains changes: ' + name)
if missing:
    run('git','-C',str(checkout),'submodule','update','--init','--depth=1','--filter=blob:none',*missing)
for name in manifest['requiredSubmodules']:
    path = checkout / name
    if output('git','-C',str(path),'rev-parse','HEAD') != manifest['submodules'][name]: refuse('Fetched submodule HEAD mismatch: ' + name)
receipt.write_text(series + '\n')
print(checkout)

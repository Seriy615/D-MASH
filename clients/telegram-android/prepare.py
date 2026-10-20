#!/usr/bin/env python3
"""Create the pinned GPL client fork; never reset an existing checkout."""
import argparse, hashlib, json, pathlib, subprocess
base = pathlib.Path(__file__).resolve().parent
manifest = json.loads((base / 'UPSTREAM.json').read_text())
parser = argparse.ArgumentParser(); parser.add_argument('checkout', type=pathlib.Path)
args = parser.parse_args(); checkout = args.checkout.resolve()
def run(*args, **kwargs): return subprocess.run(args, check=True, **kwargs)
patches = []
for entry in manifest['patches']:
    path = base / entry['path']
    if hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']: raise SystemExit('Patch digest mismatch')
    patches.append(path)
series = hashlib.sha256(''.join(entry['sha256'] for entry in manifest['patches']).encode()).hexdigest()
if not checkout.exists():
    run('git', 'clone', '--filter=blob:none', '--no-checkout', '--depth=1', manifest['repository'], str(checkout))
    run('git', '-C', str(checkout), 'fetch', '--depth=1', '--no-tags', 'origin', manifest['commit'])
    run('git', '-C', str(checkout), 'checkout', '--detach', manifest['commit'])
receipt = checkout / '.git' / 'dmash-patch-series'
if receipt.exists():
    if receipt.read_text().strip() != series: raise SystemExit('Existing fork has a different patch series; use a new checkout')
else:
    head = subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()
    if head != manifest['commit']: raise SystemExit('Existing checkout is not the pinned upstream; refusing reset')
    for patch in patches:
        run('git', '-C', str(checkout), 'apply', '--check', str(patch))
        run('git', '-C', str(checkout), 'apply', str(patch))
    receipt.write_text(series + '\n')
# Fetch only source/header modules used by this single-ABI JNI build. Other
# upstream libraries are already pinned prebuilt archives, never fabricated.
run('git','-C',str(checkout),'submodule','update','--init','--depth=1','--filter=blob:none',*manifest['requiredSubmodules'])
print(checkout)

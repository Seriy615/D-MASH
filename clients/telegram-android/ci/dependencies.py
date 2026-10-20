#!/usr/bin/env python3
"""Hash only compiler dependency outputs, never AVDs, profiles or private keys."""
import hashlib,json,os,pathlib,sys
base=pathlib.Path(os.environ['DMASH_TOOLCHAIN_CACHE'])
roots=['Qt','openssl-android-x86_64','build/quickjs-2026-06-04','archives']
receipt=base/'telegram-dependency-receipt.json'
def inventory():
    result={}
    for name in roots:
        directory=base/name
        if not directory.is_dir():raise RuntimeError('DEPENDENCY_DIRECTORY_MISSING')
        for p in directory.rglob('*'):
            if p.is_file():result[str(p.relative_to(base))]=hashlib.sha256(p.read_bytes()).hexdigest()
    if not result:raise RuntimeError('DEPENDENCY_INVENTORY_EMPTY')
    return result
if sys.argv[1]=='write':receipt.write_text(json.dumps(inventory(),sort_keys=True,indent=2)+'\n')
elif sys.argv[1]=='verify':
    if inventory()!=json.loads(receipt.read_text()):raise RuntimeError('DEPENDENCY_RECEIPT_MISMATCH')
else:raise RuntimeError('DEPENDENCY_RECEIPT_MODE')

#!/usr/bin/env python3
"""Public source/build evidence only; never copy synthetic profile directories."""
import hashlib,json,os,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[3];out=pathlib.Path(os.environ['DMASH_CI_EVIDENCE']);cache=pathlib.Path(os.environ['DMASH_TOOLCHAIN_CACHE']);out.mkdir(parents=True,exist_ok=True)
files=subprocess.check_output(['git','ls-files','clients/telegram-desktop','native','D-MASH PWA/not_messenger/js','.github/workflows/telegram-desktop-linux.yml'],cwd=root,text=True).splitlines()
record={'sourceCommit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'sourceSha256':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files},'runnerImageOS':os.environ.get('ImageOS'),'runnerImageVersion':os.environ.get('ImageVersion'),'scope':'Full original fork build evidence; acceptance only where explicit runtime report exists'}
(out/'source.json').write_text(json.dumps(record,indent=2)+'\n')
for name in ['build-telegram-desktop-fork','build-native','build-credential-host']:
 source=cache/name/'CMakeCache.txt'
 if source.exists():(out/(name+'-CMakeCache.txt')).write_bytes(source.read_bytes())

#!/usr/bin/env python3
"""Record exact sources and stage outcomes; no AVD/profile or raw runtime logs."""
import hashlib,json,os,pathlib,subprocess
out=pathlib.Path(os.environ['DMASH_CI_EVIDENCE']);out.mkdir(parents=True,exist_ok=True)
root=pathlib.Path(__file__).resolve().parents[3]
names=subprocess.check_output(['git','ls-files','native','D-MASH PWA/not_messenger/js','clients/telegram-android','.github/workflows/telegram-android.yml'],cwd=root,text=True).splitlines()
record={'sourceCommit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'sourceSha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names},'jobStatus':os.environ.get('DMASH_JOB_STATUS','IN_PROGRESS'),'runtimeReportExists':(out/'runtime.json').exists(),'note':'Package/build success does not establish UI, Account, Node or remote delivery. Only scoped runtime.json observations count.'}
(out/'pipeline.json').write_text(json.dumps(record,indent=2)+'\n')

#!/usr/bin/env python3
"""Own synthetic Git fixture: stale receipts cannot bless a different source."""
import hashlib, json, pathlib, shutil, subprocess, sys, tempfile, unittest
SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'prepare.py'
class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dmash-prepare-')
        self.root = pathlib.Path(self.temp.name); self.repo = self.root / 'repo'; self.recipe = self.root / 'recipe'
        self.repo.mkdir(); self.recipe.mkdir(); shutil.copy(SCRIPT,self.recipe/'prepare.py')
        self.git('init','-q'); self.git('config','user.email','fixture@dmash.local'); self.git('config','user.name','Synthetic fixture')
        (self.repo/'LICENSE').write_text('Synthetic test license\n'); (self.repo/'source').write_text('before\n')
        child=self.root/'subsource';child.mkdir()
        def childgit(*args):return subprocess.check_output(['git','-C',str(child),*args],text=True,stderr=subprocess.DEVNULL)
        childgit('init','-q');childgit('config','user.email','fixture@dmash.local');childgit('config','user.name','Synthetic fixture')
        (child/'file').write_text('old');childgit('add','file');childgit('commit','-qm','old');self.old_child=childgit('rev-parse','HEAD').strip()
        (child/'file').write_text('new');childgit('commit','-qam','new');self.child=childgit('rev-parse','HEAD').strip()
        self.git('-c','protocol.file.allow=always','submodule','add',str(child),'dep')
        self.git('add','LICENSE','source'); self.git('commit','-qm','base'); self.base=self.git('rev-parse','HEAD').strip()
        (self.repo/'source').write_text('after\n'); (self.repo/'added').write_text('new\n')
        self.git('add','source','added'); self.git('commit','-qm','patch')
        patch=self.git('format-patch','--stdout',self.base+'..HEAD').encode();(self.recipe/'change.patch').write_bytes(patch)
        files={name:hashlib.sha256((self.repo/name).read_bytes()).hexdigest() for name in ['source','added']}
        self.git('checkout','--detach',self.base)
        self.manifest={'repository':'unused','commit':self.base,'licenseSha256':hashlib.sha256((self.repo/'LICENSE').read_bytes()).hexdigest(),'submodules':{'dep':self.child},'requiredSubmodules':['dep'],'patches':[{'path':'change.patch','sha256':hashlib.sha256(patch).hexdigest()}],'patchedFiles':files}
        self.write_manifest(); self.assertEqual(self.prepare().returncode,0)
    def tearDown(self): self.temp.cleanup()
    def git(self,*args): return subprocess.check_output(['git','-C',str(self.repo),*args],text=True,stderr=subprocess.DEVNULL)
    def write_manifest(self): (self.recipe/'UPSTREAM.json').write_text(json.dumps(self.manifest))
    def prepare(self): return subprocess.run([sys.executable,str(self.recipe/'prepare.py'),str(self.repo)],capture_output=True,text=True)
    def test_idempotent_exact(self): self.assertEqual(self.prepare().returncode,0)
    def test_stale_receipt_new_head(self):
        self.git('add','source','added');self.git('commit','-qm','different HEAD');result=self.prepare();self.assertNotEqual(result.returncode,0);self.assertIn('HEAD',result.stderr)
    def test_license_tamper(self):
        (self.repo/'LICENSE').write_text('changed\n');result=self.prepare();self.assertNotEqual(result.returncode,0);self.assertIn('license',result.stderr)
    def test_patched_file_tamper(self):
        (self.repo/'added').write_text('changed\n');result=self.prepare();self.assertNotEqual(result.returncode,0);self.assertIn('source digest',result.stderr)
    def test_unexpected_source(self):
        (self.repo/'unexpected.java').write_text('changed\n');result=self.prepare();self.assertNotEqual(result.returncode,0);self.assertIn('Unexpected source',result.stderr)
    def test_submodule_head_stays_untouched(self):
        subprocess.run(['git','-C',str(self.repo/'dep'),'checkout','--detach',self.old_child],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        result=self.prepare();self.assertNotEqual(result.returncode,0);self.assertIn('Submodule HEAD',result.stderr)
        actual=subprocess.check_output(['git','-C',str(self.repo/'dep'),'rev-parse','HEAD'],text=True).strip();self.assertEqual(actual,self.old_child)
    def test_submodule_dirty_stays_untouched(self):
        (self.repo/'dep/file').write_text('own edit')
        result=self.prepare();self.assertNotEqual(result.returncode,0);self.assertIn('Submodule contains changes',result.stderr)
        self.assertEqual((self.repo/'dep/file').read_text(),'own edit')
    def test_submodule_map_tamper(self):
        self.manifest['submodules']={'wrong':'0'*40};self.write_manifest();result=self.prepare();self.assertNotEqual(result.returncode,0);self.assertIn('pin map',result.stderr)
if __name__ == '__main__': unittest.main()

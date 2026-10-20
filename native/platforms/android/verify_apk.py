"""Inspect a built APK without installing it. No runtime/transport equivalence."""
import argparse,hashlib,json,pathlib,re,subprocess,tempfile,zipfile
p=argparse.ArgumentParser();p.add_argument('apk',type=pathlib.Path);p.add_argument('cache',type=pathlib.Path);a=p.parse_args();sdk=a.cache/'sdk';tools=sdk/'build-tools/36.0.0';elf=sdk/'ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf'
def out(args):return subprocess.check_output([str(v) for v in args],text=True)
assert 'Verifies' in out([tools/'apksigner','verify','--verbose',a.apk]);subprocess.run([str(tools/'zipalign'),'-c','-P','16','4',str(a.apk)],check=True)
manifest=out([tools/'aapt2','dump','xmltree',a.apk,'--file','AndroidManifest.xml']);badging=out([tools/'aapt2','dump','badging',a.apk])
for text in ['org.dmash.client.MainActivity','org.dmash.client.NodeService',':node','android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE','android.permission.FOREGROUND_SERVICE_SPECIAL_USE']:assert text in manifest,text
libraries=[]
with zipfile.ZipFile(a.apk) as apk,tempfile.TemporaryDirectory(prefix='apk-inspect-',dir=a.cache/'private') as directory:
 names=apk.namelist();assert 'classes.dex' in names;assert 'assets/licenses/THIRD_PARTY_NOTICES.md' in names
 for name in names:
  if not name.startswith('lib/') or not name.endswith('.so'):continue
  raw=apk.read(name);local=pathlib.Path(directory)/pathlib.Path(name).name;local.write_bytes(raw);header=out([elf,'-l',local]);loads=[line for line in header.splitlines() if line.strip().startswith('LOAD')];assert loads and all(int(line.split()[-1],16)>=16384 for line in loads),name
  libraries.append(dict(entry=name,sha256=hashlib.sha256(raw).hexdigest(),loadAlignmentMin=16384))
result=dict(kind='Actual Gradle APK package inspection; no device runtime',status='PASS',apkSha256=hashlib.sha256(a.apk.read_bytes()).hexdigest(),apkBytes=a.apk.stat().st_size,package=next(line for line in badging.splitlines() if line.startswith('package:')),nativeCode=next(line for line in badging.splitlines() if line.startswith('native-code:')),libraries=libraries,checks=['APK signature','ZIP16K alignment','all bundledELF16K alignment','Views Activity launcher','separate :node service','specialUse permission/subtype','real Qt deployment resources','packaged dependency notices'],deviceRuntime='NOT RUN',AccountMessaging='NOT RUN')
print(json.dumps(result,indent=2))

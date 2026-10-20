"""Package link proof only; does not generate Qt deployment loader resources."""
import argparse,pathlib,subprocess,zipfile,json,hashlib,os
p=argparse.ArgumentParser();p.add_argument('cache',type=pathlib.Path);p.add_argument('repo',type=pathlib.Path);a=p.parse_args();b=a.cache.resolve();src=a.repo/'docs/native/2026-10-20/toolchain-proof';qt=b/'Qt/6.12.0/android_arm64_v8a';out=b/'android-package';sdk=b/'sdk';tools=sdk/'build-tools/36.0.0';jdk=b/'android-restored/jdk21/jdk-21.0.12.1+1';env={**os.environ,'JAVA_HOME':str(jdk),'PATH':str(jdk/'bin')+os.pathsep+os.environ['PATH']};out.mkdir(exist_ok=True)
def run(args):subprocess.run([str(x) for x in args],check=True,env=env)
run([tools/'aapt2','link','--manifest',src/'AndroidManifest.xml','-I',sdk/'platforms/android-36/android.jar','-o',out/'probe-unsigned.apk'])
libs=[b/'build-android-arm64-probe/libdmash_toolchain_service_arm64-v8a.so',sdk/'ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so']
libs += [qt/'lib'/('libQt6'+x+'_arm64-v8a.so') for x in ['Core','Network','WebSockets','Sql']]
for name in ['sqldrivers','tls','networkinformation']:
 libs+=sorted((qt/'plugins'/name).glob('*.so'))
libs += [b/'openssl-android/lib/libcrypto_3.so',b/'openssl-android/lib/libssl_3.so']
for f in libs:assert f.is_file(),f
entries=[]
with zipfile.ZipFile(out/'probe-unsigned.apk','a') as z:
 z.write(out/'dex/classes.dex','classes.dex',compress_type=zipfile.ZIP_DEFLATED)
 for f in libs:
  name='lib/arm64-v8a/'+f.name;z.write(f,name,compress_type=zipfile.ZIP_STORED);entries.append({'entry':name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
run([tools/'zipalign','-f','-P','16','4',out/'probe-unsigned.apk',out/'probe-aligned.apk'])
key=b/'private/disposable-debug.p12';key.parent.mkdir(exist_ok=True)
if not key.exists():run([jdk/'bin/keytool','-genkeypair','-keystore',key,'-storepass','synthetic-only','-keypass','synthetic-only','-alias','disposable','-keyalg','RSA','-keysize','2048','-validity','2','-dname','CN=Disposable toolchain test'])
run([tools/'apksigner','sign','--ks',key,'--ks-pass','pass:synthetic-only','--key-pass','pass:synthetic-only','--out',out/'probe-signed.apk',out/'probe-aligned.apk'])
run([tools/'apksigner','verify','--verbose',out/'probe-signed.apk'])
run([tools/'zipalign','-c','-P','16','4',out/'probe-signed.apk'])
elf=sdk/'ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf';details=[]
for f in libs:
 text=subprocess.check_output([str(elf),'-h','-l','-d',str(f)],text=True)
 assert 'AArch64' in text,f
 loads=[line for line in text.splitlines() if line.strip().startswith('LOAD')];assert loads and all(int(x.split()[-1],16)>=16384 and int(x.split()[1],16)%16384==int(x.split()[2],16)%16384 for x in loads),(f,loads)
 details.append({'file':f.name,'machine':'AArch64','load_alignment_min':16384,'dynamic_lines':[x.strip() for x in text.splitlines() if 'NEEDED' in x or 'SONAME' in x]})
result={'scope':'manual compilation/link/DEX/manifest/signature/ZIP alignment evidence only; no Qt loader resources, Android install or runtime acceptance','dex_sha256':hashlib.sha256((out/'dex/classes.dex').read_bytes()).hexdigest(),'dex_bytes':(out/'dex/classes.dex').stat().st_size,'apk_sha256':hashlib.sha256((out/'probe-signed.apk').read_bytes()).hexdigest(),'apk_bytes':(out/'probe-signed.apk').stat().st_size,'entries':entries,'elf':details,'android_runtime':'NOT RUN'}
(out/'packaging-summary-current.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS manual APK signature, all bundled ELF AArch64/16K, APK alignment; Android runtime NOT RUN')

#!/usr/bin/env python3
"""Inspect the real fork package; never imply device/UI acceptance."""
import hashlib,json,os,pathlib,re,subprocess,tempfile,zipfile
out=pathlib.Path(os.environ['DMASH_CI_EVIDENCE']);apk=out/'actual-telegram-android.apk';sdk=pathlib.Path(os.environ['ANDROID_SDK_ROOT']);build=pathlib.Path(os.environ['DMASH_ANDROID_BUILD']);tools=sdk/'build-tools/36.0.0';ndk=sdk/'ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin'
def run(*args):return subprocess.check_output([str(x) for x in args],text=True)
result={'scope':'actual Telegram fork package inspection only','status':'FAIL','runtime':'NOT_RUN','apkSha256':hashlib.sha256(apk.read_bytes()).hexdigest(),'libraries':[]}
try:
    certificate=run(tools/'apksigner','verify','--verbose','--print-certs',apk)
    result['certificateSha256']=next(x.split(': ',1)[1] for x in certificate.splitlines() if 'certificate SHA-256 digest:' in x)
    subprocess.run([str(tools/'zipalign'),'-c','-P','16','4',str(apk)],check=True)
    manifest=run(tools/'aapt2','dump','xmltree',apk,'--file','AndroidManifest.xml');badging=run(tools/'aapt2','dump','badging',apk)
    assert re.search(r"package: name='org\.dmash\.telegram\.beta'",badging),'PACKAGE_NAMESPACE'
    for token in ['org.telegram.ui.LaunchActivity','org.dmash.client.CredentialService','org.dmash.client.NodeService',':credentials',':node','android.permission.FOREGROUND_SERVICE_SPECIAL_USE']:assert token in manifest,'MANIFEST_COMPONENT'
    with zipfile.ZipFile(apk) as package,tempfile.TemporaryDirectory(prefix='fork-apk-',dir=out) as directory:
        names=package.namelist();dex=b''.join(package.read(n) for n in names if re.fullmatch(r'classes\d*\.dex',n))
        for descriptor in [b'Lorg/telegram/ui/LaunchActivity;',b'Lorg/telegram/ui/ChatActivity;',b'Lorg/telegram/ui/dmash/DmashLoginActivity;']:assert descriptor in dex,'ORIGINAL_UI_CLASS_MISSING'
        assert b'Lorg/dmash/client/NodeDiagnosticsActivity;' not in dex,'LEGACY_HARNESS_INCLUDED'
        for notice in ['assets/licenses/dmash/COPYING-TELEGRAM-GPL-2.0.txt','assets/licenses/dmash/COPYING-DMASH-CORE-MIT.txt','assets/licenses/dmash/UPSTREAM.json','assets/licenses/THIRD_PARTY_NOTICES.md']:assert notice in names,'NOTICE_MISSING'
        recipe=pathlib.Path(__file__).resolve().parents[1]
        assert package.read('assets/licenses/dmash/UPSTREAM.json')==(recipe/'UPSTREAM.json').read_bytes(),'PACKAGED_SOURCE_PROVENANCE'
        for name in names:
            if not name.startswith('lib/') or not name.endswith('.so'):continue
            assert name.startswith('lib/x86_64/'),'UNEXPECTED_ABI'
            raw=package.read(name);path=pathlib.Path(directory)/pathlib.PurePosixPath(name).name;path.write_bytes(raw)
            header=run(ndk/'llvm-readelf','-l',path);loads=[line for line in header.splitlines() if line.strip().startswith('LOAD')]
            assert loads and all(int(line.split()[-1],16)>=16384 for line in loads),'ELF_16K_ALIGNMENT'
            result['libraries'].append({'entry':name,'sha256':hashlib.sha256(raw).hexdigest()})
        for component in ['credential','node']:
            name=f'libdmash_{component}_service_x86_64.so';original=build/name;stripped=pathlib.Path(directory)/('stripped-'+name)
            subprocess.run([str(ndk/'llvm-strip'),'--strip-unneeded','-o',str(stripped),str(original)],check=True)
            shipped=package.read('lib/x86_64/'+name)
            assert hashlib.sha256(shipped).digest() in [hashlib.sha256(original.read_bytes()).digest(),hashlib.sha256(stripped.read_bytes()).digest()],'CORE_BINARY_MISMATCH'
    result['status']='PASS'
finally:(out/'package.json').write_text(json.dumps(result,indent=2)+'\n')

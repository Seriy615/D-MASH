"""Install the pinned official Qt6.12 MinGW kit into an owned runner prefix.

Qt6.12 uses a compiler-specific metadata directory that aqt3.3 does not resolve.
Archive SHA256 values come from the official package sidecars; no hash bypass.
"""
import argparse,hashlib,json,pathlib,shutil,subprocess,time,urllib.request
p=argparse.ArgumentParser();p.add_argument('prefix',type=pathlib.Path);a=p.parse_args()
prefix=a.prefix.resolve();prefix.mkdir(parents=True,exist_ok=True)
manifest=json.loads(pathlib.Path(__file__).with_name('qt6120-archives.json').read_text())
extractor=shutil.which('7z') or shutil.which('7z.exe')
if not extractor:
 candidate=pathlib.Path('C:/Program Files/7-Zip/7z.exe')
 if candidate.exists():extractor=str(candidate)
if not extractor:raise SystemExit('7-Zip is required on the Windows build runner')
downloads=prefix/'downloads';downloads.mkdir(exist_ok=True)
for item in manifest['archives']:
 target=downloads/item['archive']
 valid=target.exists() and hashlib.sha256(target.read_bytes()).hexdigest()==item['sha256']
 if not valid:
  temporary=target.with_suffix('.download')
  for attempt in range(3):
   try:
    with urllib.request.urlopen(item['url'],timeout=120) as response,temporary.open('wb') as output:shutil.copyfileobj(response,output)
    if hashlib.sha256(temporary.read_bytes()).hexdigest()!=item['sha256']:raise ValueError('Official archive SHA256 mismatch: '+item['archive'])
    temporary.replace(target);break
   except Exception:
    temporary.unlink(missing_ok=True)
    if attempt==2:raise
    time.sleep(2)
 destination=prefix/item['destination'];destination.mkdir(parents=True,exist_ok=True)
 subprocess.run([extractor,'x','-y','-o'+str(destination),str(target)],check=True,stdout=subprocess.DEVNULL)
qt=prefix/'6.12.0/mingw_64';compiler=prefix/'Tools/mingw1310_64'
# Validate the layout used by CMake and the package script before any compilation.
for name in ['lib/cmake/Qt6Core/Qt6CoreConfig.cmake','lib/cmake/Qt6Widgets/Qt6WidgetsConfig.cmake','lib/cmake/Qt6WebSockets/Qt6WebSocketsConfig.cmake','bin/windeployqt.exe']:
 if not (qt/name).is_file():raise SystemExit('Qt archive layout mismatch: '+name)
if not (compiler/'bin/g++.exe').is_file():raise SystemExit('Matching MinGW13.1 compiler archive layout mismatch')
(qt/'bin/qt.conf').write_text('[Paths]\nPrefix=..\n',encoding='utf-8')
(prefix/'installed-archives.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Pinned official Qt6.12 MinGW13.1 kit installed and checked at '+str(qt))

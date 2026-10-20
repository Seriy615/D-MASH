#!/usr/bin/env python3
"""Exact official Linux Qt modules used by the real fork and separate native core."""
import hashlib,json,pathlib,sys,urllib.request
import py7zr
cache=pathlib.Path(sys.argv[1]);base='https://download.qt.io/online/qtsdkrepository/linux_x64/desktop/qt6_6120/qt6_6120/'
revision='6.12.0-0-202609280346';host='qt.qt6.6120.linux_gcc_64'
archives=[(host,'qtbase-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z','943023b929d0c08eafe7341700b5ed7601284410b7afd6093f950be291d1d7cd'),(host,'icu-linux-Rhel8.6-x86_64.7z','1fdbcd67b1760f3a3f031c64637a9f19992aed2f35aa615e12a468f8c655d4da'),(host,'qtsvg-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z','22a7404505a2883c54556183f19adfff1cdbea30664e34bfd4171180802142e9'),('qt.qt6.6120.addons.qtwebsockets.linux_gcc_64','qtwebsockets-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z','6a8b0e642db897ae50f892a496cfbf1865d61af55205ca9e69e0c5e0e3726d09')]
records=[]
for package,name,digest in archives:
 url=base+package+'/'+revision+name;path=cache/'archives'/name;path.parent.mkdir(parents=True,exist_ok=True)
 official=urllib.request.urlopen(url+'.sha256',timeout=60).read().decode().split()[0].lower()
 if official!=digest:raise SystemExit('Official Qt archive pin differs: '+name)
 if not path.exists():
  temporary=path.with_suffix('.download')
  with urllib.request.urlopen(url,timeout=120) as response,temporary.open('wb') as out:
   while data:=response.read(1024*1024):out.write(data)
  temporary.replace(path)
 if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise SystemExit('Qt archive digest differs: '+name)
 target=cache/'Qt/6.12.0/gcc_64';target=target/'lib' if name.startswith('icu-') else target;target.mkdir(parents=True,exist_ok=True)
 with py7zr.SevenZipFile(path) as archive:archive.extractall(target)
 records.append({'url':url,'sha256':digest,'target':str(target.relative_to(cache))})
(cache/'Qt/6.12.0/gcc_64/bin/qt.conf').write_text('[Paths]\nPrefix=..\n')
(cache/'qt-ci-manifest.json').write_text(json.dumps(records,indent=2)+'\n')

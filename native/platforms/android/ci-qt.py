#!/usr/bin/env python3
"""Install the exact minimal official Qt archives used by the Android build.

Qt 6.12 moved these packages beyond aqt3.3's index selection. Every archive is
checked against both a pinned SHA256 and its official SHA256 sidecar.
"""
import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.request

REVISION = '6.12.0-0-202609280346'
BASE = 'https://download.qt.io/online/qtsdkrepository/'
HOST = BASE + 'linux_x64/desktop/qt6_6120/qt6_6120/'
ANDROID = BASE + 'all_os/android/qt6_6120/qt6_6120_x86_64/'
ARCHIVES = [
    (HOST, 'qt.qt6.6120.linux_gcc_64', 'qtbase-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z', '943023b929d0c08eafe7341700b5ed7601284410b7afd6093f950be291d1d7cd'),
    (HOST, 'qt.qt6.6120.linux_gcc_64', 'icu-linux-Rhel8.6-x86_64.7z', '1fdbcd67b1760f3a3f031c64637a9f19992aed2f35aa615e12a468f8c655d4da'),
    (HOST, 'qt.qt6.6120.addons.qtwebsockets.linux_gcc_64', 'qtwebsockets-Linux-RHEL_9_6-GCC-Linux-RHEL_9_6-X86_64.7z', '6a8b0e642db897ae50f892a496cfbf1865d61af55205ca9e69e0c5e0e3726d09'),
    (ANDROID, 'qt.qt6.6120.android_x86_64', 'qtbase-Linux-RHEL_9_6-Clang-Android-Android_ANY-X86_64.7z', '347dd1c17a499362b1eade91e5239c676cf2612cd94f4d9cc20fb4f9aa299cc8'),
    (ANDROID, 'qt.qt6.6120.addons.qtwebsockets.android_x86_64', 'qtwebsockets-Linux-RHEL_9_6-Clang-Android-Android_ANY-X86_64.7z', '58e64bc1a555a01a4a6d7da193c6c0e7e19d889213e28dedae253a9162517b80'),
]


def main():
    cache = pathlib.Path(sys.argv[1]).resolve()
    downloads = cache / 'archives'
    downloads.mkdir(parents=True, exist_ok=True)
    qt = cache / 'Qt'
    qt.mkdir(exist_ok=True)
    records = []
    for base, package, name, expected in ARCHIVES:
        url = base + package + '/' + REVISION + name
        upstream = urllib.request.urlopen(url + '.sha256', timeout=60).read().decode().split()[0].lower()
        if upstream != expected:
            raise RuntimeError('Official Qt checksum changed: ' + name)
        archive = downloads / name
        if not archive.exists():
            subprocess.run(['curl', '--fail', '--location', '--retry', '3', url, '-o', str(archive)], check=True)
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError('Qt archive checksum mismatch: ' + name)
        # Official component archives are relative to their kit; ICU is relative
        # to its lib directory. They do not contain the installer's version tree.
        relative = '6.12.0/android_x86_64' if base == ANDROID else '6.12.0/gcc_64'
        if name.startswith('icu-'):
            relative += '/lib'
        target = qt / relative
        target.mkdir(parents=True, exist_ok=True)
        subprocess.run(['7z', 'x', '-y', '-o' + str(target), str(archive)], check=True, stdout=subprocess.DEVNULL)
        records.append(dict(url=url, sha256=actual, officialSha256=upstream, target=relative))
    (qt / '6.12.0/gcc_64/bin/qt.conf').write_text('[Paths]\nPrefix=..\n')
    (cache / 'qt-ci-manifest.json').write_text(json.dumps(records, indent=2) + '\n')


if __name__ == '__main__':
    main()

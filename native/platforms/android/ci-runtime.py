#!/usr/bin/env python3
"""Actual adb UI actions + same-UID native service instrumentation on fresh AVD.

Public output contains only UI screenshots/XML, package hashes and bounded test
metadata. Synthetic scoped seed/keys stay in an app-private file and are deleted
by instrumentation. No existing user profile is imported, reset or modified.
"""
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import time
import xml.etree.ElementTree as ET

from blake3 import blake3
from nacl.signing import SigningKey

OUT = pathlib.Path(os.environ['DMASH_ANDROID_EVIDENCE'])
BUILD = pathlib.Path(os.environ['DMASH_ANDROID_BUILD'])
SERIAL = os.environ.get('ANDROID_SERIAL', 'emulator-5582')


def classify_loader(text):
    known = {
        'Use local Qt libs is false': 'QT_LIBS_DISABLED',
        'Failed to resolve the APK native libraries directory': 'APK_DIRECTORY_UNAVAILABLE',
        'The native libraries directory is null or empty': 'NATIVE_DIRECTORY_UNAVAILABLE',
        'The main library name is null or empty': 'MAIN_NAME_MISSING',
        'Loading main library failed': 'MAIN_LOAD_FAILED',
        'failed to load Qt libraries': 'QT_LIBRARY_LOAD_FAILED',
        "Can't load '": 'NATIVE_LIBRARY_LOAD_FAILED',
        'cannot locate symbol': 'NATIVE_SYMBOL_UNAVAILABLE',
        'is 32-bit instead of 64-bit': 'NATIVE_ABI_MISMATCH',
        'No ComponentInfo found for given Context': 'COMPONENT_METADATA_UNAVAILABLE',
        'Context is not an instance of Activity or Service': 'CONTEXT_UNSUPPORTED',
    }
    return {
        'events': [code for message, code in known.items() if message in text],
        'missingLibraries': sorted(set(re.findall(r'library "([A-Za-z0-9_.+\-]+\.so)" not found', text))),
    }


def adb(*args, data=None, timeout=30):
    return subprocess.check_output(['adb', '-s', SERIAL, *args], input=data, timeout=timeout)


def snapshot(name):
    adb('shell', 'uiautomator', 'dump', '/sdcard/dmash-ci-window.xml')
    raw = adb('exec-out', 'cat', '/sdcard/dmash-ci-window.xml')
    (OUT / (name + '.xml')).write_bytes(raw)
    (OUT / (name + '.png')).write_bytes(adb('exec-out', 'screencap', '-p'))
    return list(ET.fromstring(raw).iter('node'))


def element(nodes, text):
    found = [node for node in nodes if node.get('text', '').casefold() == text.casefold()]
    assert len(found) == 1, 'visible control missing/ambiguous: ' + text
    return found[0]


def tap(node, enabled=True):
    assert node.get('enabled') == ('true' if enabled else 'false')
    if enabled:
        assert node.get('clickable') == 'true'
    left, top, right, bottom = map(int, re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', node.get('bounds')).groups())
    adb('shell', 'input', 'tap', str((left + right) // 2), str((top + bottom) // 2))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    result = dict(kind='ANDROID_API35_ACTUAL_UI_AND_SCOPED_SERVICE', status='FAIL', checks=[],
                  limits=['No Account import/login/history/contacts/remote chat acceptance',
                          'No mesh peers, transit/delivery, Doze, reboot or physical device acceptance',
                          'Synthetic same-UID instrumentation grant; resident credential owner not tested'])
    try:
        apk = BUILD / 'dmash-x86_64-debug.apk'
        result['apkSha256'] = hashlib.sha256(apk.read_bytes()).hexdigest()
        result['api'] = adb('shell', 'getprop', 'ro.build.version.sdk').decode().strip()
        result['abi'] = adb('shell', 'getprop', 'ro.product.cpu.abi').decode().strip()
        result['buildFingerprint'] = adb('shell', 'getprop', 'ro.build.fingerprint').decode().strip()
        assert result['api'] == '35' and result['abi'] == 'x86_64'
        assert 'Success' in adb('install', '-r', str(apk), timeout=90).decode()
        assert 'package:' in adb('shell', 'pm', 'path', 'org.dmash.client').decode()
        result['checks'].append('actual APK installed and package path verified')
        adb('shell', 'am', 'start', '-W', '-n', 'org.dmash.client/.MainActivity')
        nodes = snapshot('01-launcher')
        assert element(nodes, 'Node is off') is not None
        for label in ['Stop Node', 'Send']:
            assert element(nodes, label).get('enabled') == 'false'
            tap(element(nodes, label), enabled=False)
        message = next(node for node in nodes if node.get('content-desc') == 'Message')
        assert message.get('enabled') == 'false'
        tap(message, enabled=False)
        nodes = snapshot('01-disabled-controls')
        assert element(nodes, 'Node is off') is not None
        tap(element(nodes, 'Application details'))
        details = snapshot('02-details')
        assert any('Account integration is in progress' in node.get('text', '') for node in details)
        tap(element(details, 'Close'))
        nodes = snapshot('03-details-closed')
        assert not any('Account integration is in progress' in node.get('text', '') for node in nodes)
        # Reopen and cancel with the Android Back control as a separate UI path.
        tap(element(nodes, 'Application details'))
        snapshot('04-details-reopened')
        adb('shell', 'input', 'keyevent', 'KEYCODE_BACK')
        nodes = snapshot('05-details-back')
        assert element(nodes, 'Application details') is not None
        adb('shell', 'input', 'keyevent', 'KEYCODE_HOME')
        adb('shell', 'am', 'start', '-W', '-n', 'org.dmash.client/.MainActivity')
        assert element(snapshot('06-resume'), 'Node is off') is not None
        result['checks'].extend(['actual details open/Close/reopen/Back taps', 'disabled Stop Node/compose/Send', 'Activity background/resume preserves honest off state'])
        # Existing 0520 identity work; distinct from session activation target22.
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            key = SigningKey.generate()
            if blake3(key.verify_key.encode().hex().encode()).hexdigest().startswith('0520'):
                break
        else:
            raise TimeoutError('synthetic identity work')
        bundle = dict(version=1, nodeSeed=key.encode().hex(), storageKey=secrets.token_hex(32), baseNcrh=secrets.token_hex(32), generation=1, directEnabled=False, endpoints=[])
        adb('shell', "run-as org.dmash.client sh -c 'umask 077; cat > files/ci-bootstrap.json'", data=json.dumps(bundle).encode())
        del bundle, key
        assert 'Success' in adb('install', '-r', str(BUILD / 'ci-instrumentation/instrumentation.apk')).decode()
        outcome = adb('shell', 'am', 'instrument', '-w', '-r', 'org.dmash.client.test/org.dmash.ci.SmokeInstrumentation', timeout=120).decode()
        # No raw instrument output is published; its dmash field is fixed text.
        summary = re.search(r'^INSTRUMENTATION_RESULT: dmash=(PASS scoped Node service:[^\n]*|FAIL [a-z-]+ [A-Za-z]+)\r?$', outcome, re.MULTILINE)
        if summary:
            result['instrumentation'] = summary.group(1).strip()
        diagnostic = re.search(r'^INSTRUMENTATION_RESULT: dmashDiagnostic=(\{[^\n]*\})\r?$', outcome, re.MULTILINE)
        if diagnostic:
            detail = json.loads(diagnostic.group(1))
            allowed = {'binderAlive', 'nativeExited', 'serviceState', 'diagnosticUnavailable'}
            assert set(detail) <= allowed
            assert detail.get('serviceState', 'OTHER') in {'STARTING', 'JNI_INSTALLED', 'START_FAILED', 'STOPPED', 'STOPPING', 'OTHER'}
            assert all(isinstance(value, bool) for name, value in detail.items() if name != 'serviceState')
            result['serviceDiagnostic'] = detail
        assert 'INSTRUMENTATION_CODE: -1' in outcome and 'PASS scoped Node service:' in outcome, 'scoped service instrumentation failed'
        result['checks'].extend(['same-UID inherited transport FD install', 'actual separate :node process + authenticated scoped node.status', 'Activity close + local IPC reconnect leaves Node running', 'FULL_ROOT_LOCK durable revoke and verified native exit', 'same private Node profile reopened under newer explicit grant', 'broker lease EOF and verified native exit'])
        result['status'] = 'PASS'
    except BaseException as error:
        result['failureClass'] = type(error).__name__
        # Fixed code only; never echo transport frames or capabilities.
        raise
    finally:
        # Native host emits only these fixed milestones under this dedicated
        # tag. Keep no raw logcat, paths, frames or unrelated process messages.
        stages = {'ENTRY', 'CORE_READY', 'BOOTSTRAP_LOOP', 'BOOTSTRAP_TIMEOUT', 'INSTALL_CALLED', 'INSTALL_REJECTED', 'FD_INSTALLED', 'STOP_REQUEST', 'HOST_ENTER', 'HOST_RETURN'}
        try:
            raw = adb('logcat', '-d', '-v', 'raw', '-s', 'DMASH_STAGE:I', '*:S', timeout=10).decode()
            result['nativeStartupStages'] = [line.strip() for line in raw.splitlines() if line.strip() in stages]
        except BaseException as error:
            result['nativeStageCollectionFailureClass'] = type(error).__name__
        try:
            raw = adb('logcat', '-d', '-v', 'raw', '-s', 'QtLoader:W', 'Qt JAVA:W', '*:S', timeout=10).decode()
            result['qtLoaderDiagnostic'] = classify_loader(raw)
        except BaseException as error:
            result['qtLoaderCollectionFailureClass'] = type(error).__name__
        (OUT / 'runtime.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()

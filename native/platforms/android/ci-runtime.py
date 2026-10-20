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
UI_STAGE = 'install'


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


def read_nodes():
    adb('shell', 'uiautomator', 'dump', '/sdcard/dmash-ci-window.xml')
    return list(ET.fromstring(adb('exec-out', 'cat', '/sdcard/dmash-ci-window.xml')).iter('node'))


def wait_ui(name, predicate, timeout=30):
    global UI_STAGE
    UI_STAGE = name
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        nodes = read_nodes()
        if predicate(nodes):
            return snapshot(name)
        time.sleep(.25)
    snapshot(name + '-timeout')
    raise TimeoutError('visible UI stage: ' + name)


def has(nodes, text, enabled=None):
    return any(n.get('text', '').casefold() == text.casefold() and
               (enabled is None or n.get('enabled') == str(enabled).lower()) for n in nodes)


def fill_fields(values):
    nodes = read_nodes()
    fields = [n for n in nodes if n.get('class') == 'android.widget.EditText']
    assert len(fields) == len(values), 'unexpected visible form fields'
    for node, value in zip(fields, values):
        tap(node)
        adb('shell', 'input', 'keyevent', 'KEYCODE_MOVE_END')
        # Long press select-all is device dependent; these forms start empty.
        if value:
            assert re.fullmatch(r'[A-Za-z0-9_-]+', value)
            adb('shell', 'input', 'text', value)
    adb('shell', 'input', 'keyevent', 'KEYCODE_BACK')


def ordinary_ui(result):
    nodes = wait_ui('01-messenger-ready', lambda n: has(n, 'Create profile', True))
    for label in ['Sign in', 'Start Node', 'Connections']:
        assert element(nodes, label).get('enabled') == 'false'
    assert not any(n.get('content-desc') == 'Message' and n.get('enabled') == 'true' for n in nodes)
    tap(element(nodes, 'Details'))
    tap(element(snapshot('02-messenger-details'), 'Node tools'))
    nodes = snapshot('03-node-tools')
    assert has(nodes, 'Node is off')
    for label in ['Stop Node', 'Send']:
        tap(element(nodes, label), enabled=False)
    message = next(n for n in nodes if n.get('content-desc') == 'Message')
    tap(message, enabled=False)
    tap(element(nodes, 'Application details'))
    details = snapshot('04-node-tools-details')
    assert any('Account integration is in progress' in n.get('text', '') for n in details)
    tap(element(details, 'Close'))
    nodes = snapshot('05-node-tools-details-closed')
    assert not any('Account integration is in progress' in n.get('text', '') for n in nodes)
    tap(element(nodes, 'Application details'))
    adb('shell', 'input', 'keyevent', 'KEYCODE_BACK')
    assert has(snapshot('06-node-tools-back'), 'Application details')
    adb('shell', 'input', 'keyevent', 'KEYCODE_HOME')
    adb('shell', 'am', 'start', '-W', '-n', 'org.dmash.client/.MainActivity')
    nodes = read_nodes()
    tap(element(nodes, 'Details'))
    tap(element(read_nodes(), 'Node tools'))
    assert has(snapshot('07-node-tools-resume'), 'Node is off')
    adb('shell', 'input', 'keyevent', 'KEYCODE_BACK')
    adb('shell', 'am', 'start', '-W', '-n', 'org.dmash.client/.MainActivity')
    nodes = wait_ui('08-main-return', lambda n: has(n, 'Create profile', True))
    result['checks'].append('ordinary launcher + explicit Node tools: unchanged disabled controls/details Close/Back/background checks')
    tap(element(nodes, 'Create profile'))
    tap(element(snapshot('09-create-profile-cancel'), 'Cancel'))
    nodes = snapshot('10-profile-cancelled')
    assert has(nodes, 'Create profile', True) and has(nodes, 'Start Node', False)
    tap(element(nodes, 'Create profile'))
    tap(element(snapshot('11-profile-empty'), 'Create profile'))
    assert has(snapshot('12-profile-validation'), 'Enter the same PIN in both fields.')
    # Cancel creates fresh empty fields for the next actual form entry.
    tap(element(read_nodes(), 'Cancel'))
    tap(element(read_nodes(), 'Create profile'))
    fill_fields(['773411', 'mismatch'])
    tap(element(read_nodes(), 'Create profile'))
    assert has(snapshot('13-profile-mismatch'), 'Enter the same PIN in both fields.')
    tap(element(read_nodes(), 'Cancel'))
    tap(element(read_nodes(), 'Create profile'))
    fill_fields(['773411', '773411'])
    tap(element(read_nodes(), 'Create profile'))
    nodes = wait_ui('14-optional-account', lambda n: has(n, 'Create and sign in'))
    tap(element(nodes, 'Cancel'))
    nodes = wait_ui('15-zero-accounts', lambda n: has(n, 'Create Account', True) and has(n, 'Start Node', True))
    assert not any(n.get('content-desc') == 'Message' and n.get('enabled') == 'true' for n in nodes)
    result['checks'].append('actual fresh Root profile Cancel/empty/mismatched PIN/valid creation; optional Account cancelled, Node available without Account')
    tap(element(nodes, 'Start Node'))
    nodes = wait_ui('16-zero-account-node', lambda n: has(n, 'Node running · 0 connected peers') or has(n, 'Could not complete this action. Your stored messages were kept.'), timeout=180)
    assert has(nodes, 'Node running · 0 connected peers'), 'actual Node enable failed'
    # Kill only the UI process, preserving separate credential/Node services.
    main_pid = adb('shell', 'pidof', 'org.dmash.client').decode().strip()
    credential_pid = adb('shell', 'pidof', 'org.dmash.client:credentials').decode().strip()
    node_pid = adb('shell', 'pidof', 'org.dmash.client:node').decode().strip()
    assert all(re.fullmatch(r'[0-9]+', pid) for pid in [main_pid, credential_pid, node_pid])
    assert len({main_pid, credential_pid, node_pid}) == 3
    adb('shell', 'run-as', 'org.dmash.client', 'kill', '-9', main_pid)
    adb('shell', 'am', 'start', '-W', '-n', 'org.dmash.client/.MainActivity')
    nodes = wait_ui('17-ui-process-reconnect', lambda n: has(n, 'Node running · 0 connected peers'))
    assert adb('shell', 'pidof', 'org.dmash.client:credentials').decode().strip() == credential_pid
    assert adb('shell', 'pidof', 'org.dmash.client:node').decode().strip() == node_pid
    tap(element(nodes, 'Stop Node and lock'))
    nodes = wait_ui('18-node-stopped-locked', lambda n: has(n, 'Node is off') and has(n, 'Unlock device', True))
    assert not adb('shell', 'sh', '-c', "'pidof org.dmash.client:node || true'").decode().strip(), 'Node process still alive after explicit stop'
    result['checks'].append('visible zero-Account Start Node; exact separate services survive UI SIGKILL/reconnect; visible Stop Node and lock verifies Node process exit')
    tap(element(nodes, 'Create Account'))
    fill_fields(['773411'])
    tap(element(read_nodes(), 'Unlock'))
    nodes = wait_ui('19-create-account', lambda n: has(n, 'Create and sign in'))
    tap(element(nodes, 'Create and sign in'))
    assert has(snapshot('20-account-empty'), 'Enter an Account name and the same password in both fields.')
    tap(element(read_nodes(), 'Cancel'))
    tap(element(read_nodes(), 'Create Account'))
    fill_fields(['android-new-ui', 'Android_New_Profile', 'android-profile-password', 'mismatch'])
    tap(element(read_nodes(), 'Create and sign in'))
    assert has(snapshot('21-account-mismatch'), 'Enter an Account name and the same password in both fields.')
    tap(element(read_nodes(), 'Cancel'))
    tap(element(read_nodes(), 'Create Account'))
    fill_fields(['android-new-ui', 'Android_New_Profile', 'android-profile-password', 'android-profile-password'])
    tap(element(read_nodes(), 'Create and sign in'))
    nodes = wait_ui('22-account-created', lambda n: has(n, 'Android_New_Profile') and has(n, 'Избранное'))
    tap(element(nodes, 'Избранное'))
    nodes = wait_ui('23-saved', lambda n: any(x.get('content-desc') == 'Message' and x.get('enabled') == 'true' for x in n))
    assert element(nodes, 'Send').get('enabled') == 'false'
    fill_fields(['Saved_from_Android_UI'])
    nodes = read_nodes()
    tap(element(nodes, 'Send'))
    nodes = wait_ui('24-saved-write', lambda n: has(n, 'Saved_from_Android_UI'))
    adb('shell', 'input', 'keyevent', 'KEYCODE_HOME')
    adb('shell', 'am', 'start', '-W', '-n', 'org.dmash.client/.MainActivity')
    nodes = wait_ui('25-account-resume', lambda n: has(n, 'Android_New_Profile'))
    if not has(nodes, 'Saved_from_Android_UI'):
        tap(element(nodes, 'Избранное'))
        nodes = wait_ui('26-history-reopened', lambda n: has(n, 'Saved_from_Android_UI'))
    tap(element(nodes, 'Sign out'))
    nodes = wait_ui('27-signed-out', lambda n: has(n, 'Sign in', True))
    assert not any(n.get('content-desc') == 'Message' and n.get('enabled') == 'true' for n in nodes)
    result['checks'].append('actual Account create validation/signin, encrypted Saved send/history, background/reopen and signout')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    result = dict(kind='ANDROID_API35_ACTUAL_UI_AND_SCOPED_SERVICE', status='FAIL', checks=[],
                  limits=['Fresh synthetic profile only; no retained profile import, contacts or remote chat acceptance',
                          'No mesh peers, transit/delivery, Doze, reboot or physical device acceptance',
                          'Separate synthetic same-UID scoped instrumentation grant is not Account transport acceptance'])
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
        ordinary_ui(result)
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
        result['uiStage'] = UI_STAGE
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

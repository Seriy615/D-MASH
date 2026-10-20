#!/usr/bin/env python3
"""Actual LaunchActivity/UI actions on this workflow's new, disposable KVM AVD.

UI actions create their own Root/Account/note. No test fixture is injected into
history, no former MainActivity harness runs, and no Telegram account is used.
"""
import hashlib,json,os,pathlib,re,secrets,shlex,subprocess,time,xml.etree.ElementTree as ET,zipfile
from loader import classify_loader
OUT=pathlib.Path(os.environ['DMASH_CI_EVIDENCE']);SERIAL=os.environ['ANDROID_SERIAL'];PKG='org.dmash.telegram.beta';GATE=os.environ.get('DMASH_UI_GATE','loader')
STAGE='install';RESULT={'scope':'actual Telegram Android fork UI','status':'FAIL','gate':GATE,'checks':[],'NodeUI':'NOT_RUN','remoteChat':'NOT_RUN','DozeReboot':'NOT_RUN','multiClientAccountBinding':'NOT_RUN'}
SAFE={'ADB_EXECUTION_FAILED','UI_CONTROL_MISSING','UI_TIMEOUT','SECRET_FIELD_SELECTOR','ORIGINAL_ACTIVITY_MISSING','CREDENTIAL_PROCESS_MISSING','CREDENTIAL_PROCESS_CHANGED','NODE_REMOTE_UI_GATES_PENDING'}
def adb(*args,data=None,timeout=30):
    try:return subprocess.check_output(['adb','-s',SERIAL,*args],input=data,stderr=subprocess.PIPE,timeout=timeout)
    except (subprocess.SubprocessError,OSError):raise RuntimeError('ADB_EXECUTION_FAILED') from None

def snapshot(name):
    adb('shell','uiautomator','dump','/sdcard/dmash-fork-window.xml')
    tree=ET.fromstring(adb('exec-out','cat','/sdcard/dmash-fork-window.xml'))
    nodes=list(tree.iter('node'))
    for node in nodes:
        if node.get('password')=='true':node.set('text','<redacted>');node.set('content-desc','<redacted>')
    (OUT/(name+'.xml')).write_bytes(ET.tostring(tree,encoding='utf-8'))
    (OUT/(name+'.png')).write_bytes(adb('exec-out','screencap','-p'))
    return nodes

def nodes():
    adb('shell','uiautomator','dump','/sdcard/dmash-fork-window.xml')
    return list(ET.fromstring(adb('exec-out','cat','/sdcard/dmash-fork-window.xml')).iter('node'))

def text(node):return node.get('text','')+' '+node.get('content-desc','')
def find(rows,label):
    matches=[n for n in rows if n.get('text','').casefold()==label.casefold() or n.get('content-desc','').casefold()==label.casefold()]
    clickable=[n for n in matches if n.get('clickable')=='true']
    if len(clickable)==1:return clickable[0]
    if len(matches)!=1:raise RuntimeError('UI_CONTROL_MISSING')
    return matches[0]
def tap(node):
    if node.get('enabled')!='true':raise RuntimeError('UI_CONTROL_MISSING')
    bounds=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',node.get('bounds',''))
    if not bounds:raise RuntimeError('UI_CONTROL_MISSING')
    a,b,c,d=map(int,bounds.groups());adb('shell','input','tap',str((a+c)//2),str((b+d)//2))
def permissions(rows):
    for n in rows:
        if n.get('resource-id','').endswith(('/permission_allow_button','/permission_allow_foreground_only_button')):tap(n);return True
    return False

def wait_ui(predicate,timeout=60):
    limit=time.monotonic()+timeout
    while time.monotonic()<limit:
        rows=nodes()
        if permissions(rows):time.sleep(.4);continue
        if predicate(rows):return rows
        time.sleep(.5)
    raise RuntimeError('UI_TIMEOUT')

def has(rows,label):return any(n.get('text','').casefold()==label.casefold() or n.get('content-desc','').casefold()==label.casefold() for n in rows)
def hide_keyboard():
    state=adb('shell','dumpsys','input_method').decode(errors='replace')
    if re.search(r'(?:mInputShown|inputShown)=true',state):adb('shell','input','keyevent','KEYCODE_BACK')
def enter(value):
    # Secrets go through stdin, never an argv/log. Values are generated only for this fresh AVD.
    adb('shell',data=('input text '+shlex.quote(value)+'\n').encode())
    time.sleep(.3);hide_keyboard()
def field(hint,index,secret=False,single=False):
    rows=nodes();edits=[n for n in rows if 'EditText' in n.get('class','')]
    matches=[n for n in edits if n.get('text')==hint or n.get('hint')==hint]
    if len(matches)==1:node=matches[0]
    elif len(edits)==(1 if single else 4):node=sorted(edits,key=lambda n:int(re.findall(r'\d+',n.get('bounds',''))[1]))[index]
    else:raise RuntimeError('UI_CONTROL_MISSING')
    if (node.get('password')=='true')!=secret:raise RuntimeError('SECRET_FIELD_SELECTOR')
    tap(node)
def credential_pid():
    value=adb('shell','pidof',PKG+':credentials').decode().strip()
    if not re.fullmatch(r'\d+',value):raise RuntimeError('CREDENTIAL_PROCESS_MISSING')
    return value

def main():
    global STAGE
    OUT.mkdir(parents=True,exist_ok=True)
    try:
        assert GATE in {'loader','fresh-account','full'}
        apk=OUT/'actual-telegram-android.apk'
        RESULT['apkSha256']=hashlib.sha256(apk.read_bytes()).hexdigest()
        adb('install','-t',str(apk),timeout=120)
        adb('logcat','-c')
        adb('shell','am','start','-W','-n',PKG+'/org.telegram.ui.LaunchActivity')
        STAGE='original-launch'
        wait_ui(lambda rows:has(rows,'D-MASH'))
        snapshot('01-actual-launch-activity')
        activity=adb('shell','dumpsys','activity','activities').decode(errors='replace')
        if 'org.telegram.ui.LaunchActivity' not in activity:raise RuntimeError('ORIGINAL_ACTIVITY_MISSING')
        RESULT['checks'].append('Actual original LaunchActivity and D-MASH Root/Account fragment visible')
        STAGE='credential-ready'
        wait_ui(lambda rows:has(rows,'Create a device Root or import your complete profile.') and any(n.get('text')=='Create device Root' and n.get('enabled')=='true' for n in rows))
        owner=credential_pid();snapshot('02-fresh-root-auth-ready')
        RESULT['checks'].append('Actual separate credential process ready; fresh Root creation enabled')
        if GATE=='loader':RESULT['status']='PASS';return
        pin='P'+secrets.token_hex(12);password='A'+secrets.token_hex(16);identity='ciowner'+secrets.token_hex(5)
        STAGE='root-create'
        field('Device PIN',0,True);enter(pin);tap(find(nodes(),'Create device Root'))
        wait_ui(lambda rows:has(rows,'Confirm device PIN'))
        field('Confirm device PIN',0,True,True);enter(pin);tap(find(nodes(),'Create'))
        wait_ui(lambda rows:has(rows,'Sign in') and has(rows,'Create Account'))
        time.sleep(2);snapshot('03-root-created')
        RESULT['checks'].append('Normal Root PIN create and confirmation UI completed')
        STAGE='account-create'
        field('Account identity',1);enter(identity)
        field('Account password',2,True);enter(password)
        field('Display name',3);enter('D-MASH-CI')
        tap(find(nodes(),'Create Account'))
        wait_ui(lambda rows:has(rows,'Sign in') and find(rows,'Sign in').get('enabled')=='true')
        time.sleep(2);snapshot('04-account-created')
        STAGE='account-login'
        field('Account password',2,True);enter(password);tap(find(nodes(),'Sign in'))
        wait_ui(lambda rows:has(rows,'Saved Messages'))
        snapshot('05-original-dialogs-account')
        RESULT['checks'].append('Actual Account created and logged in through normal UI')
        STAGE='saved-open'
        tap(find(nodes(),'Saved Messages'))
        wait_ui(lambda rows:any('EditText' in n.get('class','') for n in rows))
        snapshot('06-original-chat-saved-empty')
        note='DMASH-Saved-'+secrets.token_hex(6)
        composer=next(n for n in nodes() if 'EditText' in n.get('class',''))
        tap(composer);enter(note)
        STAGE='saved-send'
        tap(find(nodes(),'Send'))
        wait_ui(lambda rows:any(note in text(n) for n in rows) and all(note not in n.get('text','') for n in rows if 'EditText' in n.get('class','')))
        snapshot('07-original-chat-saved-accepted')
        RESULT['checks'].append('Original ChatActivity composer cleared after actual acceptance and Saved history row visible')
        STAGE='activity-background-reopen'
        adb('shell','input','keyevent','KEYCODE_HOME');time.sleep(2)
        if credential_pid()!=owner:raise RuntimeError('CREDENTIAL_PROCESS_CHANGED')
        adb('shell','am','start','-W','-n',PKG+'/org.telegram.ui.LaunchActivity')
        wait_ui(lambda rows:any(note in text(n) for n in rows));snapshot('08-original-chat-reopened')
        RESULT['checks'].append('Activity background/reopen preserves actual credential process and visible Saved note')
        if GATE=='full':
            STAGE='node-remote-ui-gates'
            raise RuntimeError('NODE_REMOTE_UI_GATES_PENDING')
        RESULT['status']='PASS'
    except BaseException as error:
        RESULT['failureClass']=type(error).__name__
        if str(error) in SAFE:RESULT['failureCode']=str(error)
        try:snapshot('failure-visible-window')
        except BaseException:pass
        raise
    finally:
        RESULT['stage']=STAGE
        try:
            stages={'ENTRY','CORE_READY','BOOTSTRAP_LOOP','BOOTSTRAP_TIMEOUT','INSTALL_CALLED','INSTALL_REJECTED','FD_INSTALLED','STOP_REQUEST','HOST_ENTER','HOST_RETURN'}
            raw=adb('logcat','-d','-v','raw','-s','DMASH_STAGE:I','*:S',timeout=10).decode(errors='replace')
            RESULT['nativeStartupStages']=[s.strip() for s in raw.splitlines() if s.strip() in stages]
            with zipfile.ZipFile(OUT/'actual-telegram-android.apk') as package:libs=[pathlib.PurePosixPath(n).name for n in package.namelist() if re.fullmatch(r'lib/[^/]+/lib[A-Za-z0-9_.+\-]+\.so',n)]
            raw=adb('logcat','-d','-v','raw','-s','QtLoader:W','Qt JAVA:W','*:S',timeout=10).decode(errors='replace')
            RESULT['qtLoaderDiagnostic']=classify_loader(raw,libs)
        except BaseException as error:RESULT['diagnosticFailureClass']=type(error).__name__
        (OUT/'runtime.json').write_text(json.dumps(RESULT,indent=2)+'\n')
if __name__=='__main__':main()

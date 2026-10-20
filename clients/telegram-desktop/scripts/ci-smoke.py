#!/usr/bin/env python3
"""Actual full-fork Intro window capture, not Root/chat acceptance or a UI mock."""
import ctypes as C,hashlib,json,os,pathlib,subprocess,tempfile,time
from PIL import ImageGrab
cache=pathlib.Path(os.environ['DMASH_TOOLCHAIN_CACHE']);out=pathlib.Path(os.environ['DMASH_CI_EVIDENCE']);bundle=out/'bundle';private=pathlib.Path(tempfile.mkdtemp(prefix='dmash-fork-ui-',dir=cache));private.chmod(0o700)
x=C.CDLL('libX11.so.6');x.XOpenDisplay.argtypes=[C.c_char_p];x.XOpenDisplay.restype=C.c_void_p;display=x.XOpenDisplay(None)
if not display:raise RuntimeError('Actual X11 display unavailable')
x.XDefaultRootWindow.argtypes=[C.c_void_p];x.XDefaultRootWindow.restype=C.c_ulong;desktop=x.XDefaultRootWindow(display)
x.XInternAtom.argtypes=[C.c_void_p,C.c_char_p,C.c_int];x.XInternAtom.restype=C.c_ulong;pid_atom=x.XInternAtom(display,b'_NET_WM_PID',0)
x.XQueryTree.argtypes=[C.c_void_p,C.c_ulong,C.POINTER(C.c_ulong),C.POINTER(C.c_ulong),C.POINTER(C.POINTER(C.c_ulong)),C.POINTER(C.c_uint)]
x.XGetWindowProperty.argtypes=[C.c_void_p,C.c_ulong,C.c_ulong,C.c_long,C.c_long,C.c_int,C.c_ulong,C.POINTER(C.c_ulong),C.POINTER(C.c_int),C.POINTER(C.c_ulong),C.POINTER(C.c_ulong),C.POINTER(C.c_void_p)]
x.XFree.argtypes=[C.c_void_p]
x.XGetGeometry.argtypes=[C.c_void_p,C.c_ulong,C.POINTER(C.c_ulong),C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(C.c_uint),C.POINTER(C.c_uint),C.POINTER(C.c_uint),C.POINTER(C.c_uint)]
x.XTranslateCoordinates.argtypes=[C.c_void_p,C.c_ulong,C.c_ulong,C.c_int,C.c_int,C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(C.c_ulong)]
def owned_window(pid):
 pending=[desktop]
 while pending:
  parent=pending.pop();root=C.c_ulong();returned_parent=C.c_ulong();children=C.POINTER(C.c_ulong)();count=C.c_uint()
  if not x.XQueryTree(display,parent,C.byref(root),C.byref(returned_parent),C.byref(children),C.byref(count)):continue
  ids=[children[i] for i in range(count.value)]
  if children:x.XFree(children)
  for window in ids:
   actual=C.c_ulong();fmt=C.c_int();items=C.c_ulong();remaining=C.c_ulong();data=C.c_void_p()
   status=x.XGetWindowProperty(display,window,pid_atom,0,1,0,0,C.byref(actual),C.byref(fmt),C.byref(items),C.byref(remaining),C.byref(data))
   value=C.cast(data,C.POINTER(C.c_ulong))[0] if status==0 and fmt.value==32 and items.value else None
   if data:x.XFree(data)
   if value==pid:
    geometry_root=C.c_ulong();gx=C.c_int();gy=C.c_int();gw=C.c_uint();gh=C.c_uint();gb=C.c_uint();gd=C.c_uint()
    if x.XGetGeometry(display,window,C.byref(geometry_root),C.byref(gx),C.byref(gy),C.byref(gw),C.byref(gh),C.byref(gb),C.byref(gd)) and gw.value>=600 and gh.value>=400:return window
   pending.append(window)
 return None
report={'scope':'Actual original Telegram full-fork Intro startup/render only','accountRootSavedFlows':'NOT_RUN','NodeTransit':'NOT_RUN'}
env=os.environ.copy();env.update({'XDG_DATA_HOME':str(private/'appdata'),'DMASH_PROFILE':str(private/'native-profile'),'QT_QPA_PLATFORM':'xcb','QT_XCB_NO_MITSHM':'1','QT_OPENGL':'software'})
process=None
try:
 with (out/'full-app-runtime.log').open('wb') as log:
  process=subprocess.Popen([str(bundle/'DMash'),'-many','-noupdate'],env=env,cwd=private,stdout=log,stderr=log)
  deadline=time.monotonic()+60;window=None
  while time.monotonic()<deadline:
   if process.poll() is not None:raise RuntimeError('Full app exited before its own X11 window: '+str(process.returncode))
   window=owned_window(process.pid)
   if window:break
   time.sleep(.1)
  if not window:raise RuntimeError('Full app X11 window did not appear')
  time.sleep(2)
  root=C.c_ulong();left=C.c_int();top=C.c_int();width=C.c_uint();height=C.c_uint();border=C.c_uint();depth=C.c_uint();child=C.c_ulong()
  if not x.XGetGeometry(display,window,C.byref(root),C.byref(left),C.byref(top),C.byref(width),C.byref(height),C.byref(border),C.byref(depth)):raise RuntimeError('Actual window geometry unavailable')
  x.XTranslateCoordinates(display,window,desktop,0,0,C.byref(left),C.byref(top),C.byref(child))
  image=ImageGrab.grab(bbox=(left.value,top.value,left.value+width.value,top.value+height.value),xdisplay=os.environ['DISPLAY'])
  if len(image.resize((100,100)).getcolors(10000) or [])<10:raise RuntimeError('Actual window capture is blank')
  image.save(out/'actual-telegram-intro.png');report.update({'result':'PASS','pid':process.pid,'window':window,'size':[width.value,height.value],'fullForkBinarySha256':hashlib.sha256((bundle/'bin/Telegram').read_bytes()).hexdigest(),'screenshotSha256':hashlib.sha256((out/'actual-telegram-intro.png').read_bytes()).hexdigest()})
except BaseException as error:
 report.update({'result':'FAIL','errorClass':type(error).__name__,'reason':str(error)});raise
finally:
 if process and process.poll() is None:
  process.terminate()
  try:process.wait(timeout=10)
  except subprocess.TimeoutExpired:process.kill();process.wait();report['ownedProcessRequiredKill']=True
 report['shutdownScope']='Owned synthetic smoke process terminated; UI-close/lifetime flow NOT_RUN'
 (out/'smoke.json').write_text(json.dumps(report,indent=2)+'\n')

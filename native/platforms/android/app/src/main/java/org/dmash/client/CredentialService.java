package org.dmash.client;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.os.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.qtproject.qt.android.bindings.QtService;
import org.json.*;
import java.io.*;
import android.system.*;
import android.util.AtomicFile;

/** Owns local credentials/Account in :credentials; :node receives only a transport FD. */
public final class CredentialService extends QtService {
 private static volatile CredentialService active;
 private static volatile IBinder node;
 private static ServiceConnection nodeConnection;
 private static final Handler main=new Handler(Looper.getMainLooper());
 static final String ACTION_STOP="org.dmash.client.LOCK_AND_STOP";
 private static native void nativeStop();
 static String profilePath(){CredentialService service=active;return service==null?"":new java.io.File(service.getFilesDir(),"profile").getAbsolutePath();}
 static boolean startNode(int fd,String profile,String device){
  CredentialService service=active;if(service==null)return false;
  CountDownLatch connected=new CountDownLatch(1);AtomicBoolean installed=new AtomicBoolean(false);
  main.post(()->{
   try{
    Intent intent=new Intent(service,NodeService.class);intent.putExtra("credentialOwner",true);service.startForegroundService(intent);
    nodeConnection=new ServiceConnection(){
     @Override public void onServiceConnected(ComponentName name,IBinder binder){
      Parcel input=Parcel.obtain(),output=Parcel.obtain();
      try(ParcelFileDescriptor channel=ParcelFileDescriptor.fromFd(fd)){
       JSONObject identity=nodeIdentity(binder);if(identity.getInt("boot")<0)throw new IOException("process identity unavailable");identity.put("device",device).put("profile",profile).put("v",1);saveReceipt(identity);
       input.writeInterfaceToken("org.dmash.client.NodeBroker.v1");input.writeTypedObject(channel,0);input.writeString(profile);
       if(!binder.transact(IBinder.FIRST_CALL_TRANSACTION,input,output,0))throw new IllegalStateException("Node install unavailable");output.readException();node=binder;installed.set(true);
       binder.linkToDeath(()->node=null,0);
      }catch(Exception ignored){}finally{input.recycle();output.recycle();connected.countDown();}
     }
     @Override public void onServiceDisconnected(ComponentName name){node=null;}
    };
    if(!service.bindService(intent,nodeConnection,Context.BIND_AUTO_CREATE))connected.countDown();
   }catch(Exception ignored){connected.countDown();}
  });
  try{return connected.await(10,TimeUnit.SECONDS)&&installed.get();}catch(InterruptedException e){Thread.currentThread().interrupt();return false;}
 }
 private static JSONObject nodeIdentity(IBinder binder)throws Exception {
  Parcel input=Parcel.obtain(),output=Parcel.obtain();try{input.writeInterfaceToken("org.dmash.client.NodeBroker.v1");if(!binder.transact(IBinder.FIRST_CALL_TRANSACTION+3,input,output,0))throw new IOException("process identity");output.readException();return new JSONObject().put("pid",output.readInt()).put("start",output.readLong()).put("boot",output.readInt());}finally{input.recycle();output.recycle();}
 }
 private static void saveReceipt(JSONObject value)throws Exception {
  CredentialService service=active;if(service==null)throw new IOException("service unavailable");File path=new File(new File(service.getFilesDir(),"profile"),"node-owner.json");AtomicFile file=new AtomicFile(path);FileOutputStream output=file.startWrite();try{Os.chmod(path.getAbsolutePath(),0600);output.write(value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));file.finishWrite(output);}catch(Exception e){file.failWrite(output);throw e;}
 }
 private static JSONObject readReceipt()throws Exception {
  CredentialService service=active;if(service==null)throw new IOException("service unavailable");try(InputStream input=new AtomicFile(new File(new File(service.getFilesDir(),"profile"),"node-owner.json")).openRead()){ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] bytes=new byte[1024];int n;while((n=input.read(bytes))>0){if(output.size()+n>4096)throw new IOException("receipt size");output.write(bytes,0,n);}return new JSONObject(output.toString("UTF-8"));}
 }
 private static boolean absent(int pid){try{Os.kill(pid,0);return false;}catch(ErrnoException e){return e.errno==OsConstants.ESRCH;}}
 private static volatile boolean proofBinding=false,proofStopRequested=false;private static volatile String proofDevice="";
 private static void beginPreviousNodeProof(String device){
  if(!device.equals(proofDevice)){proofDevice=device;proofStopRequested=false;}CredentialService service=active;if(service==null||node!=null||proofBinding)return;proofBinding=true;
  main.post(()->{ServiceConnection connection=new ServiceConnection(){public void onServiceConnected(ComponentName name,IBinder binder){node=binder;proofBinding=false;try{binder.linkToDeath(()->node=null,0);}catch(RemoteException ignored){node=null;}}public void onServiceDisconnected(ComponentName name){node=null;proofBinding=false;}};try{if(service.bindService(new Intent(service,NodeService.class),connection,0))nodeConnection=connection;else proofBinding=false;}catch(Exception ignored){proofBinding=false;}});
 }
 // 1 is actual prior-process exit; 0 is pending; -1 needs recovery. No startService here.
 private static int previousNodeProof(String device){
  CredentialService service=active;if(service==null)return -1;
  try{
   File receiptPath=new File(new File(service.getFilesDir(),"profile"),"node-owner.json");
   if(!receiptPath.exists()){
    File directory=new File(new File(service.getFilesDir(),"profile"),"node");String[] files=directory.list();if(files!=null&&files.length!=0)return -1;
    java.util.List<ActivityManager.RunningAppProcessInfo> processes=service.getSystemService(ActivityManager.class).getRunningAppProcesses();if(processes==null)return -1;for(ActivityManager.RunningAppProcessInfo process:processes)if(process.uid==android.os.Process.myUid()&&process.processName.equals(service.getPackageName()+":node"))return 0;return 1;
   }
   JSONObject receipt=readReceipt();String expected=new File(new File(service.getFilesDir(),"profile"),"node").getAbsolutePath();if(receipt.optInt("v")!=1||!device.equals(receipt.optString("device"))||!expected.equals(receipt.optString("profile")))return -1;
   int boot=android.provider.Settings.Global.getInt(service.getContentResolver(),android.provider.Settings.Global.BOOT_COUNT,-1);if(boot<0||receipt.optInt("boot",-1)<0)return -1;if(boot!=receipt.getInt("boot"))return 1;
   int pid=receipt.getInt("pid");if(pid<=0)return -1;if(absent(pid))return 1;
   IBinder binder=node;if(binder==null||!binder.isBinderAlive()){beginPreviousNodeProof(device);return 0;}JSONObject actual=nodeIdentity(binder);
   if(actual.getInt("pid")!=pid||actual.getLong("start")!=receipt.getLong("start")||actual.getInt("boot")!=boot)return -1;
   if(nativeNodeExited())return 1;
   if(!proofStopRequested){Parcel input=Parcel.obtain(),output=Parcel.obtain();try{input.writeInterfaceToken("org.dmash.client.NodeBroker.v1");if(!binder.transact(IBinder.FIRST_CALL_TRANSACTION+4,input,output,0))return -1;output.readException();proofStopRequested=true;}finally{input.recycle();output.recycle();}}
   return 0;
  }catch(Exception e){return -1;}
 }
 private static boolean nativeNodeExited(){
  IBinder binder=node;
  if(binder==null||!binder.isBinderAlive()){
   CredentialService service=active;if(service==null)return false;
   try{JSONObject receipt=readReceipt();int boot=android.provider.Settings.Global.getInt(service.getContentResolver(),android.provider.Settings.Global.BOOT_COUNT,-1);return boot>=0&&receipt.getInt("boot")>=0&&(boot!=receipt.getInt("boot")||absent(receipt.getInt("pid")));}
   catch(FileNotFoundException e){java.util.List<ActivityManager.RunningAppProcessInfo> processes=service.getSystemService(ActivityManager.class).getRunningAppProcesses();if(processes==null)return false;for(ActivityManager.RunningAppProcessInfo process:processes)if(process.uid==android.os.Process.myUid()&&process.processName.equals(service.getPackageName()+":node"))return false;return true;}
   catch(Exception e){return false;}
  }
  Parcel input=Parcel.obtain(),output=Parcel.obtain();
  try{input.writeInterfaceToken("org.dmash.client.NodeBroker.v1");if(!binder.transact(IBinder.FIRST_CALL_TRANSACTION+2,input,output,0))return false;output.readException();int pid=output.readInt();return pid>0&&output.readInt()!=0;}
  catch(Exception e){return false;}finally{input.recycle();output.recycle();}
 }
 static boolean nodeRunning(){return node!=null&&!nativeNodeExited();}
 static boolean stopNode(){
  CredentialService service=active;long deadline=SystemClock.elapsedRealtime()+10000;
  while(!nativeNodeExited()&&SystemClock.elapsedRealtime()<deadline)SystemClock.sleep(25);
  if(!nativeNodeExited())return false;
  if(service!=null)main.post(()->{if(nodeConnection!=null){try{service.unbindService(nodeConnection);}catch(IllegalArgumentException ignored){}nodeConnection=null;}service.stopService(new Intent(service,NodeService.class));});
  node=null;return true;
 }
 private static void nativeReady(){CredentialService service=active;if(service!=null)main.post(()->{PendingIntent open=PendingIntent.getActivity(service,10,new Intent(service,MainActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);PendingIntent stop=PendingIntent.getService(service,2,new Intent(service,CredentialService.class).setAction(ACTION_STOP),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);service.getSystemService(NotificationManager.class).notify(2,new Notification.Builder(service,"messages").setSmallIcon(android.R.drawable.stat_notify_chat).setContentTitle("D-MASH").setContentText("Messages service running").setContentIntent(open).setOngoing(true).addAction(new Notification.Action.Builder(null,"Lock and stop",stop).build()).build());});}
 private static void nativeFinished(int code){CredentialService service=active;if(service!=null)main.post(()->{service.stopForeground(STOP_FOREGROUND_REMOVE);service.stopSelf();});}
 @Override public void onCreate(){
  active=this;NotificationManager manager=getSystemService(NotificationManager.class);manager.createNotificationChannel(new NotificationChannel("messages","D-MASH messages",NotificationManager.IMPORTANCE_LOW));
  PendingIntent stop=PendingIntent.getService(this,2,new Intent(this,CredentialService.class).setAction(ACTION_STOP),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
  Notification notification=new Notification.Builder(this,"messages").setSmallIcon(android.R.drawable.stat_notify_chat).setContentTitle("D-MASH").setContentText("Starting messages…").setOngoing(true).addAction(new Notification.Action.Builder(null,"Lock and stop",stop).build()).build();
  if(Build.VERSION.SDK_INT>=34)startForeground(2,notification,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);else startForeground(2,notification);super.onCreate();
 }
 @Override public int onStartCommand(Intent intent,int flags,int id){if(intent!=null&&ACTION_STOP.equals(intent.getAction())){try{nativeStop();}catch(UnsatisfiedLinkError ignored){stopSelf();}return START_NOT_STICKY;}super.onStartCommand(intent,flags,id);return START_NOT_STICKY;}
 @Override public void onDestroy(){super.onDestroy();active=null;}
}

package org.dmash.client;

import android.app.*;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.*;
import org.qtproject.qt.android.bindings.QtService;

/** Separate :node process. The broker owns the duplex lease, never this Activity. */
public final class NodeService extends QtService {
 private final Handler handler=new Handler(Looper.getMainLooper());
 private static final String ACTION_STOP="org.dmash.client.STOP_NODE";
 private static volatile NodeService active;
 private String state="Starting Node…";
 private boolean installed=false;
 private ParcelFileDescriptor pending;
 private String profile;
 private final Binder localBinder=new BrokerBinder();
 public final class BrokerBinder extends Binder {
  public BrokerBinder(){attachInterface(null,"org.dmash.client.NodeBroker.v1");}
  @Override protected boolean onTransact(int code,Parcel input,Parcel output,int flags) throws RemoteException {
   if(code==INTERFACE_TRANSACTION){output.writeString("org.dmash.client.NodeBroker.v1");return true;}
   if(code==FIRST_CALL_TRANSACTION){
    input.enforceInterface("org.dmash.client.NodeBroker.v1");
    if(Binder.getCallingUid()!=android.os.Process.myUid())throw new SecurityException("caller");
    ParcelFileDescriptor fd=input.readTypedObject(ParcelFileDescriptor.CREATOR);String path=input.readString();if(input.dataAvail()!=0)throw new IllegalArgumentException("trailing data");
    install(fd,path);output.writeNoException();return true;
   }
   if(code==FIRST_CALL_TRANSACTION+1){input.enforceInterface("org.dmash.client.NodeBroker.v1");if(Binder.getCallingUid()!=android.os.Process.myUid())throw new SecurityException("caller");output.writeNoException();output.writeString(state);return true;}
   return super.onTransact(code,input,output,flags);
  }
  // Only a local, same-app credential owner can supply a transport-only bootstrap.
  public void install(ParcelFileDescriptor channel,String privateProfile) {
   if(Binder.getCallingUid()!=android.os.Process.myUid())throw new SecurityException("caller");
   if(installed||pending!=null)throw new IllegalStateException("already installed");
   if(channel==null||privateProfile==null||!privateProfile.startsWith(getFilesDir().getAbsolutePath()+"/"))throw new IllegalArgumentException("profile");
   pending=channel;profile=privateProfile;handler.post(installWhenLoaded);
  }
 }
 private final Runnable installWhenLoaded=new Runnable(){int tries=0;public void run(){
  if(pending==null)return;
  try{if(nativeInstall(pending.getFd(),profile)){installed=true;updateState("Node service is running");pending.close();pending=null;return;}}
  catch(UnsatisfiedLinkError ignored){}catch(java.io.IOException e){stopSelf();return;}
  if(++tries<100)handler.postDelayed(this,100);else stopSelf();
 }};
 private static native boolean nativeInstall(int fd,String privateProfile);
 private void updateState(String value){state=value;ServiceStatus.write(this,value);}
 private static void nativeStopped(int code){NodeService service=active;if(service!=null)service.handler.post(()->{service.updateState(code==0?"Node stopped":"Node could not start");service.stopSelf();});}
 @Override public void onCreate(){
  active=this;updateState("Starting Node…");
  NotificationManager manager=getSystemService(NotificationManager.class);
  manager.createNotificationChannel(new NotificationChannel("node","Node transport",NotificationManager.IMPORTANCE_LOW));
  PendingIntent stop=PendingIntent.getService(this,0,new Intent(this,NodeService.class).setAction(ACTION_STOP),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
  Notification notification=new Notification.Builder(this,"node").setSmallIcon(android.R.drawable.stat_notify_sync).setContentTitle("D-MASH Node").setContentText("Starting transport service").setOngoing(true).addAction(new Notification.Action.Builder(null,"Stop Node",stop).build()).build();
  if(Build.VERSION.SDK_INT>=34)startForeground(1,notification,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);else startForeground(1,notification);
  super.onCreate();
 }
 @Override public IBinder onBind(Intent intent){return localBinder;}
 @Override public int onStartCommand(Intent intent,int flags,int startId){if(intent!=null&&ACTION_STOP.equals(intent.getAction())){updateState("Node stopped");stopSelf();return START_NOT_STICKY;}super.onStartCommand(intent,flags,startId);return START_NOT_STICKY;}
 @Override public void onTimeout(int startId,int foregroundServiceType){updateState("Android stopped the Node service");stopSelf();}
 @Override public void onDestroy(){if(state.equals("Starting Node…"))updateState("Node could not start");else if(state.equals("Node service is running"))updateState("Node stopped");active=null;handler.removeCallbacksAndMessages(null);if(pending!=null)try{pending.close();}catch(java.io.IOException ignored){}super.onDestroy();}
}

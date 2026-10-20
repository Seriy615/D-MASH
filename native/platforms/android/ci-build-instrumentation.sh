#!/usr/bin/env bash
# Build a separate same-UID Android instrumentation APK; no production hooks.
set -euo pipefail
: "${DMASH_ANDROID_BUILD:?}"
: "${ANDROID_SDK_ROOT:?}"
testdir="$DMASH_ANDROID_BUILD/ci-instrumentation"
mkdir -p "$testdir/src/org/dmash/ci" "$testdir/classes" "$testdir/dex"
cat > "$testdir/src/org/dmash/ci/SmokeInstrumentation.java" <<'JAVA'
package org.dmash.ci;

import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import android.system.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import org.json.*;

/** Separate test APK. Runs as the target app UID with synthetic scoped data. */
public final class SmokeInstrumentation extends Instrumentation {
 private Context target;
 private Activity activity;
 private ParcelFileDescriptor lease;
 private DataInputStream input;
 private DataOutputStream output;
 private ServiceConnection connection;
 private IBinder binder;
 private CountDownLatch dead;
 private String phase="fixture";
 private JSONObject seedBundle;
 private JSONObject ready;
 private static void check(boolean yes,String code){if(!yes)throw new IllegalStateException(code);}
 private static JSONObject object(String text)throws Exception{return new JSONObject(text);}
 private void send(DataOutputStream stream,JSONObject value)throws Exception{
  byte[] bytes=value.toString().getBytes(StandardCharsets.UTF_8);check(bytes.length<=65536,"frame-size");stream.writeInt(bytes.length);stream.write(bytes);stream.flush();
 }
 private JSONObject receive(DataInputStream stream)throws Exception{
  int count=stream.readInt();check(count>0&&count<=524288,"reply-size");byte[] bytes=new byte[count];stream.readFully(bytes);return object(new String(bytes,StandardCharsets.UTF_8));
 }
 private Activity openActivity(){return startActivitySync(new Intent().setClassName(target,"org.dmash.client.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));}
 private void install(int generation,int revision)throws Exception{
  activity=openActivity();
  ParcelFileDescriptor[] pair=ParcelFileDescriptor.createSocketPair();lease=pair[0];
  // Duplicate only the Java stream owner; both broker references close on EOF.
  input=new DataInputStream(new ParcelFileDescriptor.AutoCloseInputStream(lease));
  output=new DataOutputStream(new ParcelFileDescriptor.AutoCloseOutputStream(ParcelFileDescriptor.dup(lease.getFileDescriptor())));
  JSONObject bundle=object(seedBundle.toString()).put("generation",generation);
  JSONObject install=new JSONObject().put("v",1).put("type","InstallTransportSession").put("request_id","android-ci").put("generation",generation).put("effective_policy_revision",revision).put("transport_bundle",bundle).put("principals",new JSONArray().put(new JSONObject().put("id","ci-broker").put("role","broker").put("ttl_seconds",120)));
  send(output,install);
  CountDownLatch bound=new CountDownLatch(1);dead=new CountDownLatch(1);
  final Throwable[] failure={null};
  connection=new ServiceConnection(){
   public void onServiceConnected(ComponentName name,IBinder service){
    binder=service;Parcel request=Parcel.obtain(),reply=Parcel.obtain();
    try{service.linkToDeath(()->dead.countDown(),0);request.writeInterfaceToken("org.dmash.client.NodeBroker.v1");request.writeTypedObject(pair[1],0);request.writeString(new File(target.getFilesDir(),"ci-native-node").getAbsolutePath());check(service.transact(IBinder.FIRST_CALL_TRANSACTION,request,reply,0),"install-transact");reply.readException();}
    catch(Throwable error){failure[0]=error;}finally{request.recycle();reply.recycle();try{pair[1].close();}catch(IOException ignored){}bound.countDown();}
   }
   public void onServiceDisconnected(ComponentName name){dead.countDown();}
  };
  Intent service=new Intent().setClassName(target,"org.dmash.client.NodeService");
  runOnMainSync(()->{target.startForegroundService(service);check(target.bindService(service,connection,Context.BIND_AUTO_CREATE),"bind");});
  check(bound.await(15,TimeUnit.SECONDS),"bind-timeout");if(failure[0]!=null)throw new IllegalStateException("binder-install",failure[0]);
  ExecutorService reader=Executors.newSingleThreadExecutor();
  try{ready=reader.submit(()->receive(input)).get(15,TimeUnit.SECONDS);}finally{reader.shutdownNow();}
  check(ready.getString("type").equals("TransportSessionReady"),"transport-not-ready");
  check(ready.getJSONArray("capabilities").length()==1,"capability-scope");
  boolean separate=false;
  for(ActivityManager.RunningAppProcessInfo process:target.getSystemService(ActivityManager.class).getRunningAppProcesses())
   if(process.processName.equals(target.getPackageName()+":node")&&process.pid!=android.os.Process.myPid())separate=true;
  check(separate,"separate-node-process");
 }
 private LocalSocket connect()throws Exception{
  LocalSocket socket=new LocalSocket();socket.connect(new LocalSocketAddress(ready.getString("endpoint"),LocalSocketAddress.Namespace.FILESYSTEM));socket.setSoTimeout(5000);
  JSONObject capability=ready.getJSONArray("capabilities").getJSONObject(0);check(capability.getString("role").equals("broker"),"broker-only");
  send(new DataOutputStream(socket.getOutputStream()),new JSONObject().put("v",1).put("id","auth").put("method","authenticate").put("params",new JSONObject().put("generation",ready.getLong("generation")).put("capability",capability.getString("token"))));
  check(receive(new DataInputStream(socket.getInputStream())).getBoolean("ok"),"authenticate");return socket;
 }
 private JSONObject rpc(LocalSocket socket,String method,JSONObject params)throws Exception{
  send(new DataOutputStream(socket.getOutputStream()),new JSONObject().put("v",1).put("id","test").put("method",method).put("params",params));
  JSONObject reply=receive(new DataInputStream(socket.getInputStream()));check(reply.getBoolean("ok"),"rpc-"+method);return reply.getJSONObject("result");
 }
 private void status()throws Exception{
  try(LocalSocket socket=connect()){
   JSONObject value=rpc(socket,"node.status",new JSONObject());
   check(value.getBoolean("initialized")&&value.getString("role").equals("NODE")&&value.getInt("connectedPeers")==0,"node-status");
  }
 }
 private void closeLease(){try{if(output!=null)output.close();}catch(IOException ignored){}try{if(input!=null)input.close();}catch(IOException ignored){}output=null;input=null;lease=null;}
 private void waitStopped()throws Exception{
  // Java onDestroy/text is insufficient. Require process/Binder death or the
  // native-return flag written after dmashRunNodeHost and its locals exit.
  long until=SystemClock.elapsedRealtime()+10000;boolean stopped=false;
  while(SystemClock.elapsedRealtime()<until){
   if(!binder.isBinderAlive()){stopped=true;break;}
   Parcel request=Parcel.obtain(),reply=Parcel.obtain();
   try{request.writeInterfaceToken("org.dmash.client.NodeBroker.v1");if(binder.transact(IBinder.FIRST_CALL_TRANSACTION+2,request,reply,0)){reply.readException();check(reply.readInt()!=android.os.Process.myPid(),"separate-stop-process");if(reply.readInt()==1){stopped=true;break;}}}
   catch(DeadObjectException ended){stopped=true;break;}
   finally{request.recycle();reply.recycle();}
   SystemClock.sleep(50);
  }
  check(stopped,"native-stop-unconfirmed");
  runOnMainSync(()->{if(connection!=null)target.unbindService(connection);});connection=null;
 }
 @Override public void onCreate(Bundle arguments){super.onCreate(arguments);start();}
 @Override public void onStart(){
  Bundle result=new Bundle();target=getTargetContext();
  try{
   File fixture=new File(target.getFilesDir(),"ci-bootstrap.json");
   byte[] bytes=java.nio.file.Files.readAllBytes(fixture.toPath());seedBundle=object(new String(bytes,StandardCharsets.UTF_8));java.util.Arrays.fill(bytes,(byte)0);check(fixture.delete(),"fixture-delete");
   phase="first-install";install(1,1);phase="first-status";status();
   // A closed Activity and closed local IPC socket do not own the Node lease.
   runOnMainSync(()->activity.finish());activity=null;phase="activity-closed-status";status();
   phase="root-lock-revoke";
   try(LocalSocket socket=connect()){JSONObject revoked=rpc(socket,"broker.revoke",new JSONObject().put("generation",1).put("revision",2).put("reason","FULL_ROOT_LOCK"));check(revoked.getLong("transportGeneration")==2,"revoke-floor");}
   closeLease();phase="root-lock-exit";waitStopped();
   // Reopen retained private Node state under a newer explicit scoped grant.
   phase="retained-reopen";install(3,4);status();closeLease();phase="lease-eof-exit";waitStopped();
   result.putString("dmash","PASS scoped Node service: same-UID FD install, separate process, authenticated node.status, Activity close/reconnect, FULL_ROOT_LOCK revoke/exit, retained-profile reopen, broker lease EOF/exit; Account/mesh/Doze/reboot NOT_RUN");
   finish(Activity.RESULT_OK,result);
  }catch(Throwable error){
   // Fixed phase/class only: transport frames/capabilities are never reported.
   result.putString("dmash","FAIL "+phase+" "+error.getClass().getSimpleName());finish(Activity.RESULT_CANCELED,result);
  }finally{
   closeLease();seedBundle=null;ready=null;
   try{if(connection!=null)target.unbindService(connection);}catch(Throwable ignored){}
   if(activity!=null)runOnMainSync(()->activity.finish());
  }
 }
}
JAVA
cat > "$testdir/AndroidManifest.xml" <<'XML'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.dmash.client.test">
 <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="36"/>
 <application android:label="D-MASH CI instrumentation"/>
 <instrumentation android:name="org.dmash.ci.SmokeInstrumentation" android:targetPackage="org.dmash.client" android:functionalTest="true"/>
</manifest>
XML
tools="$ANDROID_SDK_ROOT/build-tools/36.0.0"
android="$ANDROID_SDK_ROOT/platforms/android-36/android.jar"
javac --release 8 -cp "$android" -d "$testdir/classes" "$testdir/src/org/dmash/ci/SmokeInstrumentation.java"
jar cf "$testdir/classes.jar" -C "$testdir/classes" .
"$tools/d8" --min-api 28 --lib "$android" --output "$testdir/dex" "$testdir/classes.jar"
"$tools/aapt2" link -I "$android" --manifest "$testdir/AndroidManifest.xml" -o "$testdir/unsigned.apk"
python3 - "$testdir" <<'PY'
import pathlib,sys,zipfile
base=pathlib.Path(sys.argv[1])
with zipfile.ZipFile(base/'unsigned.apk','a') as apk:
    apk.write(base/'dex/classes.dex','classes.dex')
PY
"$tools/zipalign" -f 4 "$testdir/unsigned.apk" "$testdir/aligned.apk"
"$tools/apksigner" sign --ks "$HOME/.android/debug.keystore" --ks-pass pass:android --key-pass pass:android --out "$testdir/instrumentation.apk" "$testdir/aligned.apk"
"$tools/apksigner" verify "$testdir/instrumentation.apk"

package org.dmash.client;

import android.content.Context;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.*;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.*;

/** UI-only framed client. Closing it never locks Root or stops the resident service. */
final class CredentialConnection implements AutoCloseable {
 interface Listener {void ready(JSONObject status);void busy(boolean value);void disconnected(String code);}
 interface Reply {void received(boolean ok,String code,JSONObject result);}
 private final Context context;private final Listener listener;private final Handler main=new Handler(Looper.getMainLooper());
 private final ExecutorService reader=Executors.newSingleThreadExecutor(),writer=Executors.newSingleThreadExecutor();
 private volatile boolean closed=false,connected=false;private volatile LocalSocket socket;private DataOutputStream output;
 private String pendingId;private Reply pending;private static final int MAX=128*1024*1024;
 CredentialConnection(Context context,Listener listener){this.context=context.getApplicationContext();this.listener=listener;reader.execute(this::connectAndRead);}
 private JSONObject read(DataInputStream input)throws Exception {int length=input.readInt();if(length<=0||length>MAX)throw new IOException("frame");byte[] bytes=new byte[length];input.readFully(bytes);JSONObject reply=new JSONObject(new String(bytes,StandardCharsets.UTF_8));java.util.Arrays.fill(bytes,(byte)0);if(reply.optInt("v")!=1)throw new IOException("version");return reply;}
 private void send(String id,String method,JSONObject params)throws Exception{byte[] bytes=new JSONObject().put("v",1).put("id",id).put("method",method).put("params",params).toString().getBytes(StandardCharsets.UTF_8);if(bytes.length>MAX)throw new IOException("size");synchronized(this){output.writeInt(bytes.length);output.write(bytes);output.flush();}java.util.Arrays.fill(bytes,(byte)0);}
 private LocalSocket openSocket(String endpoint)throws IOException{LocalSocket channel=new LocalSocket();try{channel.connect(new LocalSocketAddress(endpoint,LocalSocketAddress.Namespace.FILESYSTEM));if(channel.getPeerCredentials().getUid()!=android.os.Process.myUid())throw new IOException("peer");return channel;}catch(IOException e){channel.close();throw e;}}
 private void connectAndRead(){
  try{
   long limit=SystemClock.elapsedRealtime()+15000;File locator=new File(new File(context.getFilesDir(),"profile"),"credential-endpoint.json");
   while(!closed&&SystemClock.elapsedRealtime()<limit){
    try(FileInputStream file=new FileInputStream(locator)){
     byte[] bytes=new byte[4097];int used=0,count;while(used<bytes.length&&(count=file.read(bytes,used,bytes.length-used))>0)used+=count;if(used>4096)throw new IOException("locator");JSONObject value=new JSONObject(new String(bytes,0,used,StandardCharsets.UTF_8));if(value.optInt("v")!=1)throw new IOException("locator");
     LocalSocket channel=openSocket(value.getString("endpoint"));socket=channel;output=new DataOutputStream(channel.getOutputStream());break;
    }catch(Exception e){SystemClock.sleep(100);}
   }
   if(closed)return;if(socket==null)throw new IOException("unavailable");DataInputStream input=new DataInputStream(socket.getInputStream());send("connect-status","host.status",new JSONObject());JSONObject hello=read(input);if(!hello.optBoolean("ok")||!hello.optString("id").equals("connect-status"))throw new IOException("ready");connected=true;JSONObject status=hello.getJSONObject("result").optJSONObject("value");main.post(()->{if(!closed)listener.ready(status==null?new JSONObject():status);});
   while(!closed){JSONObject reply=read(input);String id=reply.optString("id");if(id.equals("cancel"))continue;main.post(()->{if(closed)return;if(!id.equals(pendingId)){fail("CREDENTIAL_HOST_REPLY_MISMATCH");return;}Reply callback=pending;pending=null;pendingId=null;listener.busy(false);JSONObject result=reply.optJSONObject("result");if(callback!=null)callback.received(reply.optBoolean("ok"),reply.optString("code"),result==null?new JSONObject():result);});}
  }catch(Exception e){main.post(()->{if(!closed)fail("CREDENTIAL_HOST_UNAVAILABLE");});}
 }
 void request(String method,JSONObject params,Reply callback){if(closed||!connected||pending!=null){callback.received(false,"CREDENTIAL_HOST_BUSY",new JSONObject());return;}pendingId=UUID.randomUUID().toString();pending=callback;String id=pendingId;listener.busy(true);writer.execute(()->{try{send(id,method,params);}catch(Exception e){main.post(()->fail("CREDENTIAL_HOST_WRITE_FAILED"));}});main.postDelayed(()->{if(!closed&&id.equals(pendingId))fail("CREDENTIAL_HOST_TIMEOUT");},method.equals("node.enable")?180000:30000);}
 void cancel(){if(pendingId!=null&&connected)writer.execute(()->{try{send("cancel","account.cancel",new JSONObject());}catch(Exception e){main.post(()->fail("CREDENTIAL_HOST_WRITE_FAILED"));}});}
 private void fail(String code){Reply callback=pending;pending=null;pendingId=null;listener.busy(false);listener.disconnected(code);if(callback!=null)callback.received(false,code,new JSONObject());close();}
 @Override public void close(){closed=true;connected=false;try{if(socket!=null)socket.close();}catch(IOException ignored){}reader.shutdownNow();writer.shutdownNow();pending=null;pendingId=null;}
}

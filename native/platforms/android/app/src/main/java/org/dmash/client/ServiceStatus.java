package org.dmash.client;
import android.content.Context;
import android.util.AtomicFile;
import org.json.JSONObject;
import java.io.*;
final class ServiceStatus {
 static void write(Context context,String state){
  AtomicFile file=new AtomicFile(new File(context.getFilesDir(),"node-status.json"));FileOutputStream out=null;
  try{out=file.startWrite();out.write(new JSONObject().put("state",state).put("time",System.currentTimeMillis()).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));file.finishWrite(out);}
  catch(Exception ignored){if(out!=null)file.failWrite(out);}
 }
 static String read(Context context){
  try(FileInputStream in=new AtomicFile(new File(context.getFilesDir(),"node-status.json")).openRead()){
   byte[] data=new byte[4096];int used=0,n;while(used<data.length&&(n=in.read(data,used,data.length-used))>0)used+=n;return new JSONObject(new String(data,0,used,java.nio.charset.StandardCharsets.UTF_8)).optString("state","Node is off");
  }catch(Exception ignored){return "Node is off";}
 }
}

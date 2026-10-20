#!/usr/bin/env python3
"""Exercise the actual Java IPC projection with deterministic in-memory Android/core doubles.

This is a unit gate, not Android UI/service acceptance. Pass an exact prepared fork path.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CHECKOUT = Path(os.environ.get('DMASH_TELEGRAM_CHECKOUT', '/nonexistent'))
if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
    CHECKOUT = Path(sys.argv.pop(1))

STUBS = {
'android/content/Context.java': '''package android.content; public class Context {public Context getApplicationContext(){return this;} public void startService(Intent i){} public void startForegroundService(Intent i){}}''',
'android/content/Intent.java': '''package android.content; public class Intent {public Intent(Context c,Class<?> k){}}''',
'android/os/Build.java': '''package android.os; public class Build {public static class VERSION {public static int SDK_INT=36;}}''',
'android/os/Looper.java': '''package android.os; public class Looper {public static Looper getMainLooper(){return new Looper();}}''',
'android/os/Handler.java': '''package android.os; public class Handler {public Handler(Looper l){} public void removeCallbacks(Runnable r){} public void post(Runnable r){} public void postDelayed(Runnable r,long delay){}}''',
'android/widget/Toast.java': '''package android.widget; public class Toast {}''',
'org/json/JSONException.java': '''package org.json; public class JSONException extends Exception {}''',
'org/json/JSONObject.java': '''package org.json; import java.util.*; public class JSONObject {private final Map<String,Object> m=new HashMap<>(); public JSONObject put(String k,Object v)throws JSONException {m.put(k,v);return this;} public String optString(String k){return optString(k,"");} public String optString(String k,String d){Object v=m.get(k);return v instanceof String?(String)v:d;} public JSONObject optJSONObject(String k){return (JSONObject)m.get(k);} public JSONArray optJSONArray(String k){return (JSONArray)m.get(k);} public boolean optBoolean(String k){return optBoolean(k,false);} public boolean optBoolean(String k,boolean d){Object v=m.get(k);return v instanceof Boolean?(Boolean)v:d;} public int optInt(String k){return (int)optLong(k);} public long optLong(String k){Object v=m.get(k);return v instanceof Number?((Number)v).longValue():0;}}''',
'org/json/JSONArray.java': '''package org.json; import java.util.*; public class JSONArray {private final List<JSONObject> rows=new ArrayList<>();public JSONArray put(JSONObject v){rows.add(v);return this;}public int length(){return rows.size();}public JSONObject optJSONObject(int i){return rows.get(i);}}''',
'org/dmash/client/CredentialService.java': '''package org.dmash.client;public class CredentialService {}''',
'org/dmash/client/CredentialConnection.java': '''package org.dmash.client; import android.content.Context;import org.json.*;public class CredentialConnection {public interface Listener {void ready(JSONObject s);void busy(boolean b);void disconnected(String c);}public interface Reply {void received(boolean ok,String c,JSONObject r);}public static CredentialConnection current;public final Listener listener;public String method;public JSONObject params;public Reply pending;public int calls;public CredentialConnection(Context c,Listener l){listener=l;current=this;}public void request(String m,JSONObject p,Reply r){if(pending!=null)throw new AssertionError("Concurrent IPC");method=m;params=p;pending=r;calls++;listener.busy(true);}public void answer(boolean ok,String code,JSONObject result){Reply p=pending;pending=null;listener.busy(false);p.received(ok,code,result);}public void disconnect(){Reply p=pending;pending=null;listener.busy(false);listener.disconnected("CREDENTIAL_HOST_UNAVAILABLE");if(p!=null)p.received(false,"CREDENTIAL_HOST_UNAVAILABLE",new JSONObject());}public void cancel(){}}''',
'org/telegram/tgnet/TLRPC.java': '''package org.telegram.tgnet;import java.util.*;public class TLRPC {public static class User {public long id;public String first_name,last_name,phone;public boolean self,contact;public int flags;public TL_userStatusOffline status;}public static class TL_user extends User{}public static class TL_userStatusOffline{}public static class TL_peerUser {public long user_id;}public static class TL_peerNotifySettings{}public static class Dialog {public long id;public TL_peerUser peer;public TL_peerNotifySettings notify_settings;}public static class TL_dialog extends Dialog{}public static class messages_Dialogs {public ArrayList<User> users=new ArrayList<>();public ArrayList<Dialog> dialogs=new ArrayList<>();}public static class TL_messages_dialogs extends messages_Dialogs{}public static class TL_messageMediaEmpty{}public static class Message {public int id,date,flags,send_state;public long dialog_id;public String message;public boolean out,unread;public HashMap<String,String> params;public TL_peerUser peer_id,from_id;public TL_messageMediaEmpty media;}public static class TL_message extends Message{}}''',
'org/telegram/messenger/UserConfig.java': '''package org.telegram.messenger;import org.telegram.tgnet.TLRPC;public class UserConfig {static final UserConfig i=new UserConfig();public TLRPC.User user;public static UserConfig getInstance(int n){return i;}public void setCurrentUser(TLRPC.User u){user=u;}public void clearDmashCurrentUser(){user=null;}public long getClientUserId(){return user==null?0:user.id;}}''',
'org/telegram/messenger/MessagesController.java': '''package org.telegram.messenger;import org.telegram.tgnet.TLRPC;public class MessagesController {static final MessagesController i=new MessagesController();public TLRPC.messages_Dialogs dialogs;public static MessagesController getInstance(int n){return i;}public void putUser(TLRPC.User u,boolean b){}public void cleanup(){dialogs=null;}public void dmashReplaceDialogs(TLRPC.messages_Dialogs d){dialogs=d;}}''',
'org/telegram/messenger/MessagesStorage.java': '''package org.telegram.messenger;public class MessagesStorage {static final MessagesStorage i=new MessagesStorage();public static MessagesStorage getInstance(int n){return i;}public void cleanup(boolean b){}}''',
'org/telegram/messenger/MessageObject.java': '''package org.telegram.messenger;import org.telegram.tgnet.TLRPC;public class MessageObject {public static final int MESSAGE_SEND_STATE_SENT=0,MESSAGE_SEND_STATE_SENDING=1,MESSAGE_SEND_STATE_SEND_ERROR=2;public TLRPC.Message messageOwner;public MessageObject(int a,TLRPC.Message m,boolean b,boolean c){messageOwner=m;}}''',
'org/telegram/messenger/NotificationCenter.java': '''package org.telegram.messenger;import java.util.*;public class NotificationCenter {public static final int closeChats=1,appDidLogout=2,messagesDidLoad=3;static final NotificationCenter i=new NotificationCenter();public ArrayList<MessageObject> messages=new ArrayList<>();public static NotificationCenter getInstance(int n){return i;}@SuppressWarnings("unchecked")public void postNotificationName(int id,Object... args){if(id==messagesDidLoad)messages=(ArrayList<MessageObject>)args[2];if(id==closeChats)messages.clear();}}''',
# Drafts use the real SharedPreferences interface from android.jar, not these doubles.
}
HARNESS = r'''
import android.content.Context;
import org.dmash.client.CredentialConnection;
import org.json.*;
import org.telegram.messenger.*;
import org.telegram.messenger.dmash.DmashClient;
import org.telegram.messenger.dmash.MemoryPreferences;
import java.util.*;
public class PendingSendProbe {
 static JSONObject obj(Object... pairs){return DmashClient.object(pairs);}
 static void check(boolean b,String m){if(!b)throw new AssertionError(m);}
 static CredentialConnection channel(){return CredentialConnection.current;}
 static JSONObject account(String id){return obj("accountSessionActive",true,"rootLocked",false,"account",obj("accountPublicId",id,"displayName","Unit owner"));}
 static void connect(String id){DmashClient.connect(new Context());channel().listener.ready(account(id));}
 static JSONObject row(String op,int seq,String state,String text){return obj("operationId",op,"sequence",seq,"state",state,"text",text,"time",1000000L,"direction","out");}
 static void answerHistory(JSONObject... rows){JSONArray a=new JSONArray();for(JSONObject r:rows)a.put(r);check(channel().method.equals("account.history"),"history RPC");channel().answer(true,"",obj("rows",a));}
 static void history(long peer){DmashClient.loadHistory(MessagesController.getInstance(0),peer,30,0,12,2,1,0);}
 public static void main(String[] args)throws Exception {
  String owner="a".repeat(64);connect(owner);
  DmashClient.loadDialogs(MessagesController.getInstance(0));
  channel().answer(true,"",obj("rows",new JSONArray().put(obj("id","b".repeat(64),"name","Unit peer"))));
  long peer=MessagesController.getInstance(0).dialogs.dialogs.get(0).id;
  history(peer);answerHistory();
  final int[] accepted={0};
  DmashClient.sendText(peer,"one logical message",null,(ok,code,r)->{if(ok)accepted[0]++;});
  String operation=channel().params.optString("operationId");
  check(operation.matches("[0-9a-f]{64}"),"operation format");
  check(NotificationCenter.getInstance(0).messages.size()==1,"optimistic row");
  check(NotificationCenter.getInstance(0).messages.get(0).messageOwner.send_state==1,"pending clock");
  channel().disconnect();check(DmashClient.active(),"EOF preserves last known Account");check(accepted[0]==0,"unknown is not accepted");
  connect(owner);history(peer);answerHistory(row(operation,0,"HANDSHAKE_PENDING","one logical message"));
  check(NotificationCenter.getInstance(0).messages.size()==1,"sequence-zero reconciliation has one row");
  int calls=channel().calls;
  DmashClient.sendText(peer,"one logical message",null,(ok,code,r)->{if(ok)accepted[0]++;});
  check(accepted[0]==1&&calls==channel().calls,"reconciled intent clears composer without another send");
  history(peer);answerHistory(row(operation,7,"APPLICATION_PENDING","one logical message"));
  check(NotificationCenter.getInstance(0).messages.size()==1,"positive sequence replaces logical row");
  check(NotificationCenter.getInstance(0).messages.get(0).messageOwner.send_state==1,"positive sequence alone is not sent");
  history(peer);answerHistory(row(operation,7,"NODE_ACCEPTED","one logical message"));
  check(NotificationCenter.getInstance(0).messages.get(0).messageOwner.send_state==0,"actual Node custody maps sent");
  check(NotificationCenter.getInstance(0).messages.get(0).messageOwner.unread,"no fabricated recipient read");
  // A definite rejection leaves a failed row and a same-ID retry, never a new logical send.
  DmashClient.sendText(peer,"rejected text",null,(ok,code,r)->check(!ok,"rejection callback"));
  String rejected=channel().params.optString("operationId");channel().answer(false,"PEER_NOT_READY",obj());
  // send callback requests contacts then history; release both before the next explicit send.
  channel().answer(true,"",obj("rows",new JSONArray().put(obj("id","b".repeat(64),"name","Unit peer"))));answerHistory(row(operation,7,"NODE_ACCEPTED","one logical message"));
  check(NotificationCenter.getInstance(0).messages.stream().anyMatch(m->m.messageOwner.send_state==2),"definite failure row");
  DmashClient.sendText(peer,"rejected text",rejected,(ok,code,r)->{});
  check(channel().params.optString("operationId").equals(rejected),"failed-row retry identity");
  channel().disconnect();connect("c".repeat(64));
  check(NotificationCenter.getInstance(0).messages.isEmpty(),"Account switch clears old plaintext projection");
  MemoryPreferences drafts=MemoryPreferences.create();drafts.edit().putString("draft","plaintext").commit();MemoryPreferences.clearAll();
  check(drafts.getAll().isEmpty(),"Account fence clears volatile drafts");
  channel().listener.ready(obj("accountSessionActive",false,"rootLocked",true));
  check(!DmashClient.active()&&UserConfig.getInstance(0).user==null,"Root lock clears Account and current user");
  System.out.println("PASS: unknown/reconciled/positive-sequence/rejected-retry/Account-fence/draft-memory");
 }
}
'''

class PendingSendTest(unittest.TestCase):
    def test_actual_projection_state_machine(self):
        java_home=Path(os.environ['JAVA_HOME'])
        sdk=Path(os.environ['ANDROID_HOME'])
        source=CHECKOUT/'TMessagesProj/src/main/java'
        self.assertTrue((source/'org/telegram/messenger/dmash/DmashClient.java').is_file())
        with tempfile.TemporaryDirectory(prefix='dmash-android-projection-unit-') as directory:
            root=Path(directory)
            for name,text in STUBS.items():
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
            (root/'PendingSendProbe.java').write_text(HARNESS)
            files=[str(p) for p in root.rglob('*.java')]
            files += [str(source/'org/telegram/messenger/dmash'/name) for name in ['DmashClient.java','MemoryPreferences.java']]
            subprocess.run([str(java_home/'bin/javac'),'-cp',str(sdk/'platforms/android-36/android.jar'),'-d',str(root/'classes'),*files],check=True)
            subprocess.run([str(java_home/'bin/java'),'-cp',str(root/'classes')+os.pathsep+str(sdk/'platforms/android-36/android.jar'),'PendingSendProbe'],check=True)

if __name__=='__main__':unittest.main()

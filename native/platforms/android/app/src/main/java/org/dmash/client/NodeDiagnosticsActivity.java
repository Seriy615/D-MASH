package org.dmash.client;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.*;
import android.content.*;
import android.widget.*;

/** Native Views UI. Account and UI lifetimes do not own the Node process. */
public final class NodeDiagnosticsActivity extends Activity {
 private TextView status;
 private Button stopNode;
 private boolean bound=false;
 private final ServiceConnection connection=new ServiceConnection(){
  @Override public void onServiceConnected(ComponentName name,IBinder binder){
   Parcel input=Parcel.obtain(),output=Parcel.obtain();
   try{input.writeInterfaceToken("org.dmash.client.NodeBroker.v1");binder.transact(IBinder.FIRST_CALL_TRANSACTION+1,input,output,0);output.readException();String serviceState=output.readString();status.setText(serviceState);stopNode.setEnabled("Node service is running".equals(serviceState));binder.linkToDeath(()->runOnUiThread(()->{status.setText(ServiceStatus.read(NodeDiagnosticsActivity.this));stopNode.setEnabled(false);}),0);}
   catch(Exception ignored){status.setText("Node status is unavailable");stopNode.setEnabled(false);}finally{input.recycle();output.recycle();}
  }
  @Override public void onServiceDisconnected(ComponentName name){status.setText(ServiceStatus.read(NodeDiagnosticsActivity.this));stopNode.setEnabled(false);}
 };
 @Override public void onResume(){super.onResume();status.setText(ServiceStatus.read(this));stopNode.setEnabled(false);bound=bindService(new Intent(this,NodeService.class),connection,0);if(!bound&&status.getText().toString().equals("Node service is running"))status.setText("Node is off");}
 @Override public void onPause(){if(bound){unbindService(connection);bound=false;}super.onPause();}
 @Override public void onCreate(Bundle state) {
  super.onCreate(state);
  LinearLayout page=new LinearLayout(this);page.setOrientation(LinearLayout.VERTICAL);page.setPadding(24,24,24,24);
  TextView title=new TextView(this);title.setText("D-MASH");title.setTextSize(26);page.addView(title);
  status=new TextView(this);status.setText("Node is off");status.setContentDescription("Node status");page.addView(status);
  stopNode=new Button(this);stopNode.setText("Stop Node");stopNode.setEnabled(false);stopNode.setOnClickListener(v->{startService(new Intent(this,NodeService.class).setAction(NodeService.ACTION_STOP));status.setText("Stopping Node…");stopNode.setEnabled(false);});page.addView(stopNode);
  Button details=new Button(this);details.setText("Application details");details.setOnClickListener(v->new AlertDialog.Builder(this).setTitle("D-MASH").setMessage("Development version. Account integration is in progress. Your existing messages and identity will be preserved during import.").setNegativeButton("Close",null).show());page.addView(details);
  TextView chats=new TextView(this);chats.setText("Conversations");chats.setTextSize(20);page.addView(chats);
  TextView empty=new TextView(this);empty.setText("Connect your existing Account to see conversations. Account import is not available in this checkpoint.");page.addView(empty,new LinearLayout.LayoutParams(-1,0,1));
  EditText message=new EditText(this);message.setHint("Message");message.setContentDescription("Message");message.setEnabled(false);page.addView(message);
  Button send=new Button(this);send.setText("Send");send.setEnabled(false);page.addView(send);
  setContentView(page);
 }
}

package org.dmash.toolchain;
import android.content.Intent;
import org.qtproject.qt.android.bindings.QtService;
public final class ProbeService extends QtService {
  private static native int nativeProbe();
  @Override public int onStartCommand(Intent intent,int flags,int id) {
    return super.onStartCommand(intent,flags,id);
  }
}

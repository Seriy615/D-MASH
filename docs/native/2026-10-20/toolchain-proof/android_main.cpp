// Disposable JNI/link skeleton; not a tested Android runtime or Node implementation.
#include <jni.h>
#include <QCoreApplication>
#include <QSqlDatabase>
#include <QSslSocket>
#include <QWebSocket>
extern "C" {
#include "quickjs.h"
}
extern "C" JNIEXPORT jint JNICALL Java_org_dmash_toolchain_ProbeService_nativeProbe(JNIEnv*,jclass){
 JSRuntime*rt=JS_NewRuntime();JSContext*ctx=JS_NewContext(rt);JSValue v=JS_Eval(ctx,"21*2",4,"synthetic",JS_EVAL_TYPE_GLOBAL);int32_t n=0;JS_ToInt32(ctx,&n,v);JS_FreeValue(ctx,v);JS_FreeContext(ctx);JS_FreeRuntime(rt);
 auto drivers=QSqlDatabase::drivers();QWebSocket socket;auto qt=QCoreApplication::applicationName();auto tls=QSslSocket::supportsSsl();(void)drivers;(void)socket;(void)qt;(void)tls;return n;
}
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*,void*){return JNI_VERSION_1_6;}
int main(int argc,char**argv){qputenv("ANDROID_OPENSSL_SUFFIX","_3");QCoreApplication app(argc,argv);return app.exec();}

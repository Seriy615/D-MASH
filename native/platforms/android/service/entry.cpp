#include <jni.h>
#include <unistd.h>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <QByteArray>
#include <QCoreApplication>
#include <QMetaObject>
#include <QtCore/private/qandroidextras_p.h>
#include <QJniObject>
#include <QString>
// Reuse the CLI's real actor/bootstrap owner instead of creating another protocol.
int dmashRunNodeHost(QCoreApplication&,int,char**);
namespace {std::mutex mutex;std::condition_variable ready;int descriptor=-1;QByteArray profile;bool installed=false,stopping=false;}
extern "C" JNIEXPORT jboolean JNICALL Java_org_dmash_client_NodeService_nativeInstall(JNIEnv* env,jclass,jint fd,jstring path){
 std::lock_guard<std::mutex> guard(mutex);if(installed||stopping||fd<0||!path)return false;
 const char* raw=env->GetStringUTFChars(path,nullptr);if(!raw)return false;profile=QByteArray(raw);env->ReleaseStringUTFChars(path,raw);
 descriptor=dup(fd);if(descriptor<0){profile.clear();return false;}installed=true;ready.notify_one();return true;
}
extern "C" JNIEXPORT void JNICALL Java_org_dmash_client_NodeService_nativeRequestStop(JNIEnv*,jclass){
 {std::lock_guard<std::mutex> guard(mutex);stopping=true;ready.notify_all();}
 if(auto* app=QCoreApplication::instance())QMetaObject::invokeMethod(app,&QCoreApplication::quit,Qt::QueuedConnection);
}
int main(int argc,char** argv){
 QAndroidService app(argc,argv);
 std::unique_lock<std::mutex> lock(mutex);
 if(!ready.wait_for(lock,std::chrono::seconds(15),[]{return installed||stopping;})){QJniObject::callStaticMethod<void>("org/dmash/client/NodeService","nativeStopped","(I)V",jint(1));return 1;}
 if(stopping){lock.unlock();QJniObject::callStaticMethod<void>("org/dmash/client/NodeService","nativeStopped","(I)V",jint(0));return 0;}
 QByteArray name="dmash-node-service",p="--profile",f="--bootstrap-fd",number=QByteArray::number(descriptor);
 char* args[]={name.data(),p.data(),profile.data(),f.data(),number.data(),nullptr};lock.unlock();
 int code=dmashRunNodeHost(app,5,args);
 QJniObject::callStaticMethod<void>("org/dmash/client/NodeService","nativeStopped","(I)V",jint(code));
 return code;
}

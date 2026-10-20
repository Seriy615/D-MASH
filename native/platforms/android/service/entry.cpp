#include <jni.h>
#include <unistd.h>
#include <mutex>
#include <QEventLoop>
#include <QTimer>
#include <QByteArray>
#include <QCoreApplication>
#include <QMetaObject>
#include <QtCore/private/qandroidextras_p.h>
#include <QJniObject>
#include <QString>
// Reuse the CLI's real actor/bootstrap owner instead of creating another protocol.
int dmashRunNodeHost(QCoreApplication&,int,char**);
namespace {std::mutex mutex;QEventLoop* bootstrapLoop=nullptr;int descriptor=-1;QByteArray profile;bool installed=false,stopping=false;}
extern "C" JNIEXPORT jboolean JNICALL Java_org_dmash_client_NodeService_nativeInstall(JNIEnv* env,jclass,jint fd,jstring path){
 std::lock_guard<std::mutex> guard(mutex);if(installed||stopping||fd<0||!path)return false;
 const char* raw=env->GetStringUTFChars(path,nullptr);if(!raw)return false;profile=QByteArray(raw);env->ReleaseStringUTFChars(path,raw);
 descriptor=dup(fd);if(descriptor<0){profile.clear();return false;}installed=true;if(bootstrapLoop)QMetaObject::invokeMethod(bootstrapLoop,&QEventLoop::quit,Qt::QueuedConnection);return true;
}
extern "C" JNIEXPORT void JNICALL Java_org_dmash_client_NodeService_nativeRequestStop(JNIEnv*,jclass){
 {std::lock_guard<std::mutex> guard(mutex);stopping=true;if(bootstrapLoop)QMetaObject::invokeMethod(bootstrapLoop,&QEventLoop::quit,Qt::QueuedConnection);}
 if(auto* app=QCoreApplication::instance())QMetaObject::invokeMethod(app,&QCoreApplication::quit,Qt::QueuedConnection);
}
int main(int argc,char** argv){
 QAndroidService app(argc,argv);
 // QAndroidService schedules its Java startup handshake on a zero-delay timer.
 // Pump that event before waiting for Java to return and supply the descriptor.
 QEventLoop bootstrap;QTimer timeout;timeout.setSingleShot(true);
 QObject::connect(&timeout,&QTimer::timeout,&bootstrap,&QEventLoop::quit);
 std::unique_lock<std::mutex> lock(mutex);
 if(!installed&&!stopping){bootstrapLoop=&bootstrap;lock.unlock();timeout.start(15000);bootstrap.exec();lock.lock();bootstrapLoop=nullptr;}
 if(!installed&&!stopping){lock.unlock();QJniObject::callStaticMethod<void>("org/dmash/client/NodeService","nativeStopped","(I)V",jint(1));return 1;}
 if(stopping){lock.unlock();QJniObject::callStaticMethod<void>("org/dmash/client/NodeService","nativeStopped","(I)V",jint(0));return 0;}
 QByteArray name="dmash-node-service",p="--profile",f="--bootstrap-fd",number=QByteArray::number(descriptor);
 char* args[]={name.data(),p.data(),profile.data(),f.data(),number.data(),nullptr};lock.unlock();
 int code=dmashRunNodeHost(app,5,args);
 QJniObject::callStaticMethod<void>("org/dmash/client/NodeService","nativeStopped","(I)V",jint(code));
 return code;
}

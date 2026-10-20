// Bounded link-only probe, not the Android service/JNI broker API.
#include "js_actor.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <jni.h>
extern "C" JNIEXPORT jint JNICALL Java_org_dmash_probe_LinkProbe_nativeLink(JNIEnv*,jclass){
    if(!QCoreApplication::instance())return -1;
    try{QTemporaryDir profile;if(!profile.isValid())return -2;dmash::JsActor actor(profile.path());actor.close();return 0;}catch(...){return -3;}
}

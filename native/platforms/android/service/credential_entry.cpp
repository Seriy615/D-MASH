#include <credential_host.h>
#include <node_supervisor.h>
#include <daemon_rpc.h>
#include <account_service.h>
#include <QtCore/private/qandroidextras_p.h>
#include <QJniObject>
#include <QJniEnvironment>
#include <QJsonDocument>
#include <QJsonArray>
#include <QLocalSocket>
#include <QDir>
#include <QtEndian>
#include <QMetaObject>
#include <QElapsedTimer>
#include <QThread>
#include <sys/socket.h>
#include <unistd.h>
namespace {
void need(bool value,const char* code){if(!value)throw dmash::account::AccountError(code);}
class AndroidNode final:public dmash::credential::NodeSupervisor {
 std::unique_ptr<QLocalSocket> lease_;QString profile_,device_;QJsonObject stoppedFloors_,ready_;bool recoveryPending_=false,renewal_=false;
 bool waitPrevious(dmash::broker::RootCodec::Current current){auto device=QJniObject::fromString(device_);QJniObject::callStaticMethod<void>("org/dmash/client/CredentialService","beginPreviousNodeProof","(Ljava/lang/String;)V",device.object<jstring>());QElapsedTimer timer;timer.start();while(timer.elapsed()<10000){need(current&&current(),"CREDENTIAL_CANCELLED");int state=QJniObject::callStaticMethod<jint>("org/dmash/client/CredentialService","previousNodeProof","(Ljava/lang/String;)I",device.object<jstring>());if(state==1){recoveryPending_=false;return true;}if(state<0)return false;QThread::msleep(50);}return false;}
 void send(const QJsonObject& value){auto bytes=QJsonDocument(value).toJson(QJsonDocument::Compact);QByteArray frame(4,0);qToBigEndian<quint32>(bytes.size(),frame.data());frame+=bytes;bool written=lease_&&lease_->write(frame)==frame.size()&&lease_->waitForBytesWritten(5000);bytes.fill(0);frame.fill(0);need(written,"NODE_BOOTSTRAP_FAILED");}
 QJsonObject receive(){auto exact=[&](int length){QByteArray bytes;while(bytes.size()<length){if(!lease_->bytesAvailable())need(lease_->waitForReadyRead(5000),"NODE_BOOTSTRAP_FAILED");auto block=lease_->read(length-bytes.size());need(!block.isEmpty(),"NODE_BOOTSTRAP_FAILED");bytes+=block;}return bytes;};auto header=exact(4);auto size=qFromBigEndian<quint32>(header.constData());need(size>0&&size<=65536,"NODE_BOOTSTRAP_FAILED");auto bytes=exact(size);QJsonParseError error;auto result=QJsonDocument::fromJson(bytes,&error).object();bytes.fill(0);need(error.error==QJsonParseError::NoError,"NODE_BOOTSTRAP_FAILED");return result;}
public:
 explicit AndroidNode(QString profile):profile_(std::move(profile)){}
 ~AndroidNode(){try{stop();}catch(...){}}
 bool running()const override{return QJniObject::callStaticMethod<jboolean>("org/dmash/client/CredentialService","nodeRunning","()Z");}
 bool provePreviousStopped(const dmash::broker::ControlState& state,dmash::broker::RootCodec::Current current)override{device_=state.deviceId;recoveryPending_=true;return waitPrevious(std::move(current));}
 QJsonObject takeStoppedFloors()override{auto result=stoppedFloors_;stoppedFloors_={};return result;}
 QJsonArray renewCapabilities()override{need(running()&&lease_&&renewal_,"NODE_LEASE_RENEWAL_UNSUPPORTED");QJsonArray result;for(const auto& id:{QString("credential-owner"),QString("account-owner")}){auto requestId=id+"-renew";send(QJsonObject{{"v",1},{"type","RenewCapabilityLease"},{"request_id",requestId},{"principal",id},{"ttl_seconds",id=="credential-owner"?86400:3600}});auto reply=receive();QString token;for(const auto& value:ready_.value("capabilities").toArray()){auto cap=value.toObject();if(cap.value("id")==id)token=cap.value("token").toString();}need(reply.value("v")==1&&reply.value("type")=="CapabilityLeaseRenewed"&&reply.value("request_id")==requestId&&reply.value("id")==id&&reply.value("generation")==ready_.value("generation")&&!token.isEmpty()&&reply.value("token")==token,"NODE_CAPABILITY_RENEWAL_FAILED");result.append(reply);}return result;}
 void stop()override{lease_.reset();if(recoveryPending_)need(waitPrevious([]{return true;}),"NODE_PREVIOUS_EXIT_UNCONFIRMED");need(QJniObject::callStaticMethod<jboolean>("org/dmash/client/CredentialService","stopNode","()Z"),"NODE_STOP_UNCONFIRMED");}
 QJsonObject start(const dmash::broker::BrokerResult& session)override{
  need(!running(),"NODE_ALREADY_RUNNING");stop();stoppedFloors_={};ready_={};renewal_=false;device_=session.control.deviceId;need(QDir().mkpath(profile_),"NODE_PROFILE_UNAVAILABLE");int pair[2];need(::socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)==0,"NODE_BOOTSTRAP_FAILED");
  lease_=std::make_unique<QLocalSocket>();if(!lease_->setSocketDescriptor(pair[0],QLocalSocket::ConnectedState,QIODevice::ReadWrite)){::close(pair[0]);::close(pair[1]);throw dmash::account::AccountError("NODE_BOOTSTRAP_FAILED");}
  auto path=QJniObject::fromString(profile_);auto device=QJniObject::fromString(device_);bool installed=QJniObject::callStaticMethod<jboolean>("org/dmash/client/CredentialService","startNode","(ILjava/lang/String;Ljava/lang/String;)Z",jint(pair[1]),path.object<jstring>(),device.object<jstring>());::close(pair[1]);
  QJsonObject candidateFloors;try{
   need(installed,"NODE_SERVICE_UNAVAILABLE");QJsonObject install{{"v",1},{"type","InstallTransportSession"},{"request_id","credential-owner"},{"generation",double(session.control.generation)},{"effective_policy_revision",double(session.control.policyRevision)},{"transport_bundle",session.transportBundle},{"principals",QJsonArray{QJsonObject{{"id","credential-owner"},{"role","broker"},{"ttl_seconds",86400}},QJsonObject{{"id","account-owner"},{"role","owner"},{"ttl_seconds",3600}}}}};send(install);auto ready=receive();if(ready.value("type")=="STALE_FLOOR"){auto generation=ready.value("minTransportGeneration").toInteger();auto revision=ready.value("minPolicyRevision").toInteger();need(ready.value("v")==1&&ready.value("request_id")=="credential-owner"&&generation>=1&&generation<=9007199254740991LL&&revision>=1&&revision<=9007199254740991LL,"NODE_BOOTSTRAP_FAILED");candidateFloors=ready;throw dmash::account::AccountError("NODE_STALE_FLOOR");}auto epoch=ready.value("generation").toInteger();need(ready.value("v")==1&&ready.value("type")=="TransportSessionReady"&&ready.value("request_id")=="credential-owner"&&epoch>=1&&epoch<=9007199254740991LL,"NODE_BOOTSTRAP_FAILED");dmash::credential::DaemonRpc proof;proof.install(ready);auto status=proof.call("status","node.status",{},true);need(status.value("ownerGeneration").toInteger()==epoch&&status.value("transportGeneration").toInteger()==qint64(session.control.generation)&&status.value("policyRevision").toInteger()==qint64(session.control.policyRevision),"NODE_SESSION_BINDING_INVALID");ready_=ready;renewal_=ready.value("features").toObject().value("capabilityLeaseRenewal").toBool();return ready;
  }catch(...){stop();stoppedFloors_=candidateFloors;throw;}
 }
};
}
extern "C" JNIEXPORT void JNICALL Java_org_dmash_client_CredentialService_nativeStop(JNIEnv*,jclass){if(auto* app=QCoreApplication::instance())QMetaObject::invokeMethod(app,&QCoreApplication::quit,Qt::QueuedConnection);}
int main(int argc,char** argv){QAndroidService app(argc,argv);int result=0;try{auto path=QJniObject::callStaticObjectMethod("org/dmash/client/CredentialService","profilePath","()Ljava/lang/String;").toString();need(!path.isEmpty(),"PROFILE_DIRECTORY_UNAVAILABLE");auto node=std::make_shared<AndroidNode>(QDir(path).filePath("node"));{dmash::credential::CredentialHost host(path,node);QJniObject::callStaticMethod<void>("org/dmash/client/CredentialService","nativeReady","()V");result=app.exec();}}catch(...){result=1;}QJniObject::callStaticMethod<void>("org/dmash/client/CredentialService","nativeFinished","(I)V",jint(result));return result;}

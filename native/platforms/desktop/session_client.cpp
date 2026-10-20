#include "session_client.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QStringDecoder>
#include <QtEndian>
#ifdef Q_OS_UNIX
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#endif
SessionClient::SessionClient(QObject* p):QObject(p) {
 socket_.setReadBufferSize(65540);
 timeout_.setSingleShot(true); timeout_.setInterval(5000);
 connect(&timeout_,&QTimer::timeout,this,[this]{fail(tr("Service request timed out"));});
 connect(&socket_,&QLocalSocket::connected,this,[this]{send("auth","authenticate",{{"generation",generation_},{"capability",token_}}); token_.fill(QChar(0)); token_.clear();});
 connect(&socket_,&QLocalSocket::readyRead,this,&SessionClient::read);
 connect(&socket_,&QLocalSocket::disconnected,this,[this]{fail(tr("Service disconnected; accepted transport jobs remain with the service"));});
 connect(&socket_,&QLocalSocket::errorOccurred,this,[this](QLocalSocket::LocalSocketError){fail(tr("Service connection failed"));});
}
SessionClient::~SessionClient(){token_.fill(QChar(0));}
void SessionClient::fail(const QString& m){timeout_.stop();authenticated_=false;token_.fill(QChar(0));token_.clear();input_.fill(0);input_.clear();length_=0;socket_.abort();emit stateChanged(m,false);}
void SessionClient::disconnectSession(){fail(tr("UI detached; Node service lifetime is independent"));}
bool SessionClient::attachDescriptor(int fd) {
#ifdef Q_OS_UNIX
 // The broker gives UI a separate one-shot same-UID socket, never its daemon lease.
 struct ucred peer{};socklen_t size=sizeof(peer);
 if(fd<0||getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)||peer.uid!=geteuid()){fail(tr("Private broker channel required"));return false;}
 QByteArray raw;
 auto exact=[&](int n){while(raw.size()<n){pollfd p{fd,POLLIN,0};if(poll(&p,1,1000)!=1)return false;char b[4096];auto count=::read(fd,b,qMin<int>(sizeof(b),n-raw.size()));if(count<=0)return false;raw.append(b,count);}return true;};
 if(!exact(4)){::close(fd);fail(tr("Broker handoff incomplete"));return false;}
 auto n=qFromBigEndian<quint32>(raw.constData());raw.clear();
 if(!n||n>65536||!exact(n)){::close(fd);raw.fill(0);fail(tr("Broker handoff invalid"));return false;}
 ::close(fd);
 QStringDecoder utf8(QStringDecoder::Utf8);utf8.decode(raw);QJsonParseError error;auto doc=QJsonDocument::fromJson(raw,&error);raw.fill(0);
 auto v=doc.object();auto endpoint=v.value("endpoint").toString();token_=v.value("capability").toString();generation_=v.value("generation").toInteger();
 if(utf8.hasError()||error.error!=QJsonParseError::NoError||v.value("v").toInt()!=1||v.value("role").toString()!="owner"||!endpoint.startsWith('/')||token_.size()!=64||generation_<=0||v.value("expiresAt").toInteger()<=QDateTime::currentMSecsSinceEpoch()) {fail(tr("Broker handoff rejected"));return false;}
 emit stateChanged(tr("Connecting to local Node service…"),false);timeout_.start();socket_.connectToServer(endpoint);return true;
#else
 Q_UNUSED(fd);fail(tr("Windows authenticated broker handle support is pending"));return false;
#endif
}
void SessionClient::send(const QString& id,const QString& method,const QJsonObject& params){
 auto bytes=QJsonDocument(QJsonObject{{"v",1},{"id",id},{"method",method},{"params",params}}).toJson(QJsonDocument::Compact);QByteArray frame(4,0);qToBigEndian<quint32>(bytes.size(),frame.data());frame+=bytes;
 if(socket_.bytesToWrite()+frame.size()>65536||socket_.write(frame)!=frame.size()){frame.fill(0);bytes.fill(0);fail(tr("Local request failed"));return;}frame.fill(0);bytes.fill(0);timeout_.start();
}
void SessionClient::refresh(){if(authenticated_&&!timeout_.isActive())send("status","node.status",{});}
void SessionClient::read(){
 while(socket_.bytesAvailable()){
  if(!length_){input_+=socket_.read(4-input_.size());if(input_.size()<4)return;length_=qFromBigEndian<quint32>(input_.constData());input_.clear();if(!length_||length_>65536){fail(tr("Invalid service response"));return;}}
  input_+=socket_.read(length_-input_.size());if(input_.size()<length_)return;
  QStringDecoder utf8(QStringDecoder::Utf8);utf8.decode(input_);QJsonParseError err;auto doc=QJsonDocument::fromJson(input_,&err);input_.fill(0);input_.clear();length_=0;
  if(utf8.hasError()||err.error!=QJsonParseError::NoError||!doc.isObject()){fail(tr("Invalid service response"));return;}
  auto obj=doc.object();timeout_.stop();if(!obj.value("ok").toBool()){emit stateChanged(tr("Service refused request; Account integration is pending"),authenticated_);continue;}
  if(obj.value("id").toString()=="auth"){auto result=obj.value("result").toObject();if(result.value("role").toString()!="owner"||result.value("generation").toInteger()!=generation_){fail(tr("Service session mismatch"));return;}authenticated_=true;emit stateChanged(tr("Local service authenticated; network availability is unverified"),true);refresh();}
  else if(obj.value("id").toString()=="status")emit nodeStatus(obj.value("result").toObject());
 }
}

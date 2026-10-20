#include "credential_client.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QProcess>
#include <QSignalBlocker>
#include <QUuid>
#include <QtEndian>
#include <QStringDecoder>
#ifdef Q_OS_UNIX
#include <sys/socket.h>
#include <unistd.h>
#endif
#ifdef Q_OS_WIN
#include "os_windows.h"
#endif
namespace {constexpr quint32 MaximumFrame=128*1024*1024;}
CredentialClient::CredentialClient(QString directory,QObject* parent):QObject(parent),directory_(std::move(directory)){
 connectTimer_.setInterval(100);deadline_.setSingleShot(true);deadline_.setInterval(30000);
 connect(&connectTimer_,&QTimer::timeout,this,&CredentialClient::connectHost);
 connect(&deadline_,&QTimer::timeout,this,[this]{fail("CREDENTIAL_HOST_TIMEOUT");});
 connect(&socket_,&QLocalSocket::connected,this,[this]{
#ifdef Q_OS_UNIX
  ucred peer{};socklen_t size=sizeof(peer);if(getsockopt(socket_.socketDescriptor(),SOL_SOCKET,SO_PEERCRED,&peer,&size)||peer.uid!=geteuid()){fail("CREDENTIAL_HOST_PEER_MISMATCH");return;}
#endif
#ifdef Q_OS_WIN
  try{dmash::windowsLocal::requireSameUserPipe(quintptr(socket_.socketDescriptor()));dmash::windowsLocal::requirePrivatePipe(quintptr(socket_.socketDescriptor()));}catch(...){fail("CREDENTIAL_HOST_PEER_MISMATCH");return;}
#endif
  connectTimer_.stop();send("ready","host.status",{});
 });
 connect(&socket_,&QLocalSocket::readyRead,this,&CredentialClient::read);
 connect(&socket_,&QLocalSocket::disconnected,this,[this]{ready_=false;if(busy())fail("CREDENTIAL_HOST_DISCONNECTED");});
 connect(&socket_,&QLocalSocket::errorOccurred,this,[this](QLocalSocket::LocalSocketError){if(!ready_&&!connectTimer_.isActive())connectTimer_.start();else if(ready_)fail("CREDENTIAL_HOST_DISCONNECTED");});
}
void CredentialClient::request(const QString& method,const QJsonObject& params){if(busy())return;method_=method;params_=params;id_=QUuid::createUuid().toString(QUuid::Id128);emit busyChanged(true);deadline_.start(method=="node.enable"?180000:30000);if(ready_&&socket_.state()==QLocalSocket::ConnectedState){send(id_,method_,params_);params_={};}else{attempts_=0;connectHost();if(busy())connectTimer_.start();}}
void CredentialClient::connectHost(){if(socket_.state()==QLocalSocket::ConnectedState||socket_.state()==QLocalSocket::ConnectingState)return;if(++attempts_>150){fail("CREDENTIAL_HOST_UNAVAILABLE");return;}
 QFile file(QDir(directory_).filePath("credential-endpoint.json"));if((launched_||attempts_==1)&&file.open(QIODevice::ReadOnly)&&file.size()<=4096){auto locator=QJsonDocument::fromJson(file.readAll()).object();auto endpoint=locator.value("endpoint").toString();if(locator.value("v").toInt()==1&&!endpoint.isEmpty()){socket_.connectToServer(endpoint);return;}}
 if(!launched_){auto executable=QCoreApplication::instance()->property("dmashCredentialHost").toString();auto node=QCoreApplication::instance()->property("dmashNodeHost").toString();if(executable.isEmpty())executable=QDir(QCoreApplication::applicationDirPath()).filePath("dmash-credential-host");if(node.isEmpty())node=QDir(QCoreApplication::applicationDirPath()).filePath("dmash-node-host");
#ifdef Q_OS_WIN
 if(!executable.endsWith(".exe"))executable+=".exe";if(!node.endsWith(".exe"))node+=".exe";
#endif
 launched_=QProcess::startDetached(executable,{"--profile",directory_,"--node-host",node});if(!launched_)fail("CREDENTIAL_HOST_LAUNCH_FAILED");}
}
void CredentialClient::send(const QString& id,const QString& method,const QJsonObject& params){auto bytes=QJsonDocument(QJsonObject{{"v",1},{"id",id},{"method",method},{"params",params}}).toJson(QJsonDocument::Compact);if(bytes.size()>MaximumFrame){fail("CREDENTIAL_REQUEST_TOO_LARGE");return;}QByteArray frame(4,0);qToBigEndian<quint32>(bytes.size(),frame.data());frame+=bytes;const bool accepted=socket_.write(frame)==frame.size();bytes.fill(0);frame.fill(0);if(!accepted)fail("CREDENTIAL_HOST_WRITE_FAILED");}
void CredentialClient::cancel(){if(!busy())return;if(ready_)send("cancel","account.cancel",{});else fail("ACCOUNT_SESSION_CHANGED");}
void CredentialClient::fail(const QString& code){connectTimer_.stop();deadline_.stop();ready_=false;auto method=std::move(method_);method_.clear();{QSignalBlocker blocked(&socket_);socket_.abort();}input_.fill(0);input_.clear();length_=0;params_={};if(!method.isEmpty()){emit busyChanged(false);emit response(method,false,code,{});}}
void CredentialClient::read(){while(socket_.bytesAvailable()){
 if(!length_){input_+=socket_.read(4-input_.size());if(input_.size()<4)return;length_=qFromBigEndian<quint32>(input_.constData());input_.clear();if(!length_||length_>MaximumFrame){fail("CREDENTIAL_HOST_BAD_FRAME");return;}}
 input_+=socket_.read(length_-input_.size());if(input_.size()<length_)return;QStringDecoder utf8(QStringDecoder::Utf8);utf8.decode(input_);QJsonParseError error;auto message=QJsonDocument::fromJson(input_,&error).object();input_.fill(0);input_.clear();length_=0;if(utf8.hasError()||error.error!=QJsonParseError::NoError||message.value("v").toInt()!=1){fail("CREDENTIAL_HOST_BAD_REPLY");return;}
 auto id=message.value("id").toString();if(id=="cancel")continue;if(id=="ready"){if(!message.value("ok").toBool()){fail(message.value("code").toString());return;}ready_=true;emit hostStatusReady(message.value("result").toObject().value("value").toObject());if(busy()){send(id_,method_,params_);params_={};}continue;}if(id!=id_){fail("CREDENTIAL_HOST_REPLY_MISMATCH");return;}deadline_.stop();auto method=std::move(method_);method_.clear();emit busyChanged(false);emit response(method,message.value("ok").toBool(),message.value("code").toString(),message.value("result").toObject());
}}

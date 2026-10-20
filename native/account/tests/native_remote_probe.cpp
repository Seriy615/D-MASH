// Interactive synthetic Account owner. Private fixture/ready files and pipes
// carry credentials/history; stdout is consumed privately by the parent test.
#include "account_service.h"
#include "broker_service.h"
#include "daemon_rpc.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QSet>
#include <QThread>
#include <atomic>
#include <cstdlib>
#include <iostream>
using namespace dmash;
static void need(bool b,const char* code){if(!b)throw account::AccountError(code);}
static QJsonObject read(const QString& path){QFile file(path);need(file.open(QIODevice::ReadOnly),"REMOTE_PRIVATE_INPUT");auto raw=file.readAll();auto doc=QJsonDocument::fromJson(raw);raw.fill(0);need(doc.isObject(),"REMOTE_INPUT_JSON");return doc.object();}
static void output(const QJsonObject& value){std::cout<<QJsonDocument(value).toJson(QJsonDocument::Compact).constData()<<std::endl;}
static QJsonObject result(const account::AccountResult& value){return {{"ok",value.ok},{"code",value.code},{"value",value.value},{"rows",value.rows}};}
int main(int argc,char** argv){
 QCoreApplication app(argc,argv);
 try{
  need(argc==4,"REMOTE_ARGUMENTS");const auto fixture=read(QString::fromLocal8Bit(argv[1])),ready=read(QString::fromLocal8Bit(argv[3]));
  QDir directory(QString::fromLocal8Bit(argv[2]));need(directory.exists(),"REMOTE_DIRECTORY");
  auto profile=fixture.value("profile").toObject();auto storage=QByteArray::fromHex(fixture.value("ownerStorageKey").toString().toLatin1());need(storage.size()==32,"REMOTE_STORAGE_KEY");
  const auto pin=fixture.value("rootPin").toString().toUtf8();const auto credentials=directory.filePath("credentials.db");
  if(!QFile::exists(credentials)){
   auto proof=broker::RootCodec::openExisting(profile.value("root").toObject(),pin,[]{return true;});
   auto imported=broker::CredentialStore::importProfile(credentials,storage,profile,proof,directory.filePath("original.backup"),[]{return true;});
  }
  broker::BrokerService broker(credentials,storage,directory.filePath("control.db"));need(broker.unlock(pin).get().ok,"REMOTE_ROOT_UNLOCK");
  credential::DaemonRpc rpc;rpc.install(ready);std::atomic<bool> crashBeforeConsume{false};QSet<QString> applications;bool loseSubmitReply=false;QHash<QString,QJsonObject> submitted;int identicalRetries=0;
  account::AccountService::RegistryReader registry=[&](const QJsonArray& rows){auto r=broker.readAccountRegistry(rows).get();need(r.ok,"REMOTE_REGISTRY");return r.accountRegistry;};
  account::AccountService::Transport transport=[&](const QString& scope,const QString& method,const QJsonObject& params){
   if(method=="inbox.commitConsumption"&&crashBeforeConsume&&applications.contains(params.value("recordHandle").toString()))std::_Exit(73);
   auto value=rpc.call(scope,method,params);
   if(method=="job.submit"){
    const auto operation=params.value("operationId").toString();
    if(submitted.contains(operation)){const auto previous=submitted.value(operation);need(previous.value("expiresAt")==params.value("expiresAt")&&previous.value("id")==value.value("id"),"REMOTE_RETRY_CHANGED");++identicalRetries;}
    else submitted.insert(operation,{{"expiresAt",params.value("expiresAt")},{"id",value.value("id")}});
    if(loseSubmitReply){loseSubmitReply=false;QThread::msleep(25);throw account::AccountError("ACCOUNT_TRANSPORT_FAILED");}
   }
   if(method=="inbox.list")for(const auto& row:value.value("records").toArray()){
    const auto record=row.toObject();const auto payload=QJsonDocument::fromJson(record.value("payload").toString().toUtf8()).object();
    if(payload.value("type")=="ACCOUNT_APP_V4")applications.insert(record.value("handle").toString());
   }
   return value;
  };
  std::unique_ptr<account::AccountService> service;
  auto open=[&]{
   service=std::make_unique<account::AccountService>(directory.filePath("account.db"),transport,registry);
   if(!QFile::exists(directory.filePath("imported.marker"))){auto imported=service->importProfile(profile).get();need(imported.ok&&imported.importProof.has_value(),"REMOTE_IMPORT");need(broker.confirmAccountImport(*imported.importProof).get().ok,"REMOTE_PUBLICATION");QFile marker(directory.filePath("imported.marker"));need(marker.open(QIODevice::WriteOnly),"REMOTE_MARKER");marker.write("published");marker.close();}
   auto login=service->login(fixture.value("identity").toString(),fixture.value("password").toString().toUtf8()).get();
   need(login.ok&&login.value.value("accountPublicId")==fixture.value("accountPublicId"),"REMOTE_IDENTITY_CHANGED");
  };
  open();output({{"ok",true},{"sameAccountPublicId",true}});
  std::string line;
  while(std::getline(std::cin,line)){
   need(line.size()<=16384,"REMOTE_COMMAND_LIMIT");auto command=QJsonDocument::fromJson(QByteArray::fromStdString(line)).object();line.assign(line.size(),'\0');
   const auto method=command.value("method").toString(),peer=fixture.value("peer").toString();
   if(method=="sync")output(result(service->sync().get()));
   else if(method=="send")output(result(service->sendText(peer,command.value("operationId").toString(),command.value("text").toString()).get()));
   else if(method=="history")output(result(service->listHistory(peer).get()));
   else if(method=="contacts")output(result(service->listContacts().get()));
   else if(method=="armLostSubmitReply"){loseSubmitReply=true;output({{"ok",true}});}
   else if(method=="retryStats")output({{"ok",true},{"identicalRetries",identicalRetries}});
   else if(method=="armCrashBeforeConsume"){crashBeforeConsume=true;output({{"ok",true}});}
   else if(method=="reopen"){need(service->logout().get().ok,"REMOTE_LOGOUT");service.reset();rpc.install(ready);open();output({{"ok",true},{"sameAccountPublicId",true}});}
   else if(method=="logout"){output(result(service->logout().get()));}
   else if(method=="quit")break;
   else output({{"ok",false},{"code","REMOTE_UNKNOWN_COMMAND"}});
  }
  return 0;
 }catch(const std::exception& error){output({{"ok",false},{"code",QString::fromLatin1(error.what())}});return 1;}
}

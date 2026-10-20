#include "account_controller.h"
#include "profile_key.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QUuid>
AccountController::AccountController(QString path,QObject* parent):QObject(parent){
 const QString directory=QFileInfo(path).absolutePath();
 profileDirectory_=directory;auto key=openAppLocalKey(directory,path);
 broker_=std::make_shared<dmash::broker::BrokerService>(QDir(directory).filePath("credentials.sqlite"),key,QDir(directory).filePath("control.sqlite"));key.fill(0);
 auto registry=[broker=broker_](const QJsonArray& rows){auto result=broker->readAccountRegistry(rows).get();if(!result.ok)throw dmash::account::AccountError(result.code.toUtf8().constData());return result.accountRegistry;};
 service_=std::make_unique<dmash::account::AccountService>(path,dmash::account::AccountService::Transport{},registry);poll_.setInterval(40);
 connect(&poll_,&QTimer::timeout,this,[this]{
 if(pendingBroker_){if(pendingBroker_->wait_for(std::chrono::seconds(0))!=std::future_status::ready)return;auto result=pendingBroker_->get();pendingBroker_.reset();poll_.stop();emit busyChanged(false);if(!result.ok){pendingProfile_={};emit failed(result.code);return;}if(!pendingProfile_.isEmpty()){auto profile=std::move(pendingProfile_);pendingProfile_={};watch(service_->importProfile(profile),"import");}else loadAccounts();return;}
 if(!pending_||pending_->wait_for(std::chrono::seconds(0))!=std::future_status::ready)return;auto result=pending_->get();pending_.reset();poll_.stop();const auto kind=kind_;emit busyChanged(false);
 if(!result.ok){if(result.code=="ROOT_UNLOCK_REQUIRED")emit rootUnlockRequired();else emit failed(result.code);return;}
 if(kind=="accounts")emit accountsReady(result.rows);
 else if(kind=="import")loadAccounts();
 else if(kind=="login"){emit signedIn(result.value);contacts();}
 else if(kind=="logout")emit signedOut();
 else if(kind=="contacts")emit contactsReady(result.rows);
 else if(kind=="history")emit historyReady(result.rows);
 else if(kind=="send"){operationId_.clear();emit sent(result.value);}
 });
}
void AccountController::watch(std::future<dmash::account::AccountResult> future,QString kind){kind_=kind;pending_=std::make_unique<std::future<dmash::account::AccountResult>>(std::move(future));emit busyChanged(true);poll_.start();}
void AccountController::loadAccounts(){if(!busy())watch(service_->listAccounts(),"accounts");}
void AccountController::importProfile(const QJsonObject& v,const QString& pin){if(busy())return;pendingProfile_=v;pendingBroker_=std::make_unique<std::future<dmash::broker::BrokerResult>>(broker_->importProfile(v,pin.toUtf8(),QDir(profileDirectory_).filePath("original-profile.backup")));emit busyChanged(true);poll_.start();}
void AccountController::unlockRoot(const QString& pin){if(busy())return;pendingBroker_=std::make_unique<std::future<dmash::broker::BrokerResult>>(broker_->unlock(pin.toUtf8()));emit busyChanged(true);poll_.start();}
void AccountController::login(const QString& id,const QString& password){if(!busy())watch(service_->login(id,password.toUtf8()),"login");}
void AccountController::logout(){if(!busy())watch(service_->logout(),"logout");}
void AccountController::cancel(){service_->cancel();if(pendingBroker_)broker_->cancel();}
void AccountController::contacts(){if(!busy())watch(service_->listContacts(),"contacts");}
void AccountController::history(const QString& peer){if(!busy())watch(service_->listHistory(peer),"history");}
void AccountController::send(const QString& peer,const QString& text){if(busy())return;if(operationId_.isEmpty()||peer!=pendingPeer_||text!=pendingText_)operationId_=QUuid::createUuid().toString(QUuid::Id128)+QUuid::createUuid().toString(QUuid::Id128);pendingPeer_=peer;pendingText_=text;watch(service_->sendText(peer,operationId_,text),"send");}

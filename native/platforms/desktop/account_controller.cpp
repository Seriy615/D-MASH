#include "account_controller.h"
#include <QFileInfo>
#include <QUuid>
#include <stdexcept>
AccountController::AccountController(QString path,QObject* parent):QObject(parent){
 if(QFileInfo(path).fileName()!="account.sqlite")throw std::runtime_error("PROFILE_PATH_RECOVERY_REQUIRED");
 client_=std::make_unique<CredentialClient>(QFileInfo(path).absolutePath(),this);
 connect(client_.get(),&CredentialClient::busyChanged,this,&AccountController::busyChanged);
 connect(client_.get(),&CredentialClient::response,this,[this](const QString& method,bool ok,const QString& code,const QJsonObject& result){
  if(!ok){if(code=="ROOT_UNLOCK_REQUIRED"){emit signedOut();emit rootUnlockRequired();}else{if(code=="CREDENTIAL_HOST_DISCONNECTED"||code=="CREDENTIAL_HOST_UNAVAILABLE")emit signedOut();emit failed(code);}return;}
  const auto value=result.value("value").toObject();const auto rows=result.value("rows").toArray();
  if(method=="account.listAccounts"||method=="profile.import"||method=="root.unlock"){emit accountsReady(rows);const auto active=value.value("activeAccount").toObject();if(!active.isEmpty()){emit signedIn(active);contacts();}}
  else if(method=="account.login"){emit signedIn(value);contacts();}
  else if(method=="account.logout")emit signedOut();
  else if(method=="account.contacts")emit contactsReady(rows);
  else if(method=="account.history")emit historyReady(rows);
  else if(method=="account.sendText"){if(value.value("accepted").toBool())operationId_.clear();emit sent(value);}
 });
}
void AccountController::loadAccounts(){client_->request("account.listAccounts");}
void AccountController::importProfile(const QJsonObject& profile,const QString& pin){client_->request("profile.import",{{"profile",profile},{"pin",pin}});}
void AccountController::unlockRoot(const QString& pin){client_->request("root.unlock",{{"pin",pin}});}
void AccountController::login(const QString& identity,const QString& password){client_->request("account.login",{{"identity",identity},{"password",password}});}
void AccountController::logout(){client_->request("account.logout");}
void AccountController::cancel(){client_->cancel();}
void AccountController::contacts(){client_->request("account.contacts");}
void AccountController::history(const QString& peer){client_->request("account.history",{{"peer",peer},{"before",0},{"limit",50}});}
void AccountController::send(const QString& peer,const QString& text){if(busy())return;if(operationId_.isEmpty()||peer!=pendingPeer_||text!=pendingText_)operationId_=QUuid::createUuid().toString(QUuid::Id128)+QUuid::createUuid().toString(QUuid::Id128);pendingPeer_=peer;pendingText_=text;client_->request("account.sendText",{{"peer",peer},{"operationId",operationId_},{"text",text}});}

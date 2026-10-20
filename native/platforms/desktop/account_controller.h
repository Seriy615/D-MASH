#pragma once
#include "credential_client.h"
#include <QObject>
#include <QJsonArray>
#include <memory>
class AccountController final:public QObject {
 Q_OBJECT
public:
 explicit AccountController(QString profile,QObject* parent=nullptr);
 void loadAccounts();void importProfile(const QJsonObject&,const QString& rootPin);void unlockRoot(const QString&);
 void createProfile(const QString& pin);void createAndSignIn(const QString& identity,const QString& password,const QString& displayName);
 void login(const QString&,const QString&);void logout();void cancel();
 void nodeStatus();void enableNode(const QJsonArray& endpoints,bool direct);void disableNode();
 void contacts();void history(const QString&);void send(const QString&,const QString&);
 bool busy()const{return client_->busy();}
signals:
 void nodeStopped();void hostStatusReady(const QJsonObject&);
 void profileCreated();
 void accountAdded(const QJsonObject&);
 void busyChanged(bool);void rootUnlockRequired();
 void accountsReady(const QJsonArray&);void signedIn(const QJsonObject&);void signedOut();
 void contactsReady(const QJsonArray&);void historyReady(const QJsonArray&);
 void sent(const QJsonObject&);void failed(const QString&);
private:
 std::unique_ptr<CredentialClient> client_;
 QString pendingPeer_,pendingText_,operationId_;
 QString createIdentity_,createPassword_;
};

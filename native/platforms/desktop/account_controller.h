#pragma once
#include <account_service.h>
#include <broker_service.h>
#include <QObject>
#include <QTimer>
#include <QJsonArray>
#include <memory>
class AccountController final:public QObject {
 Q_OBJECT
public:
 explicit AccountController(QString profile,QObject* parent=nullptr);
 void loadAccounts();void importProfile(const QJsonObject&,const QString& rootPin);void unlockRoot(const QString&);
 void login(const QString&,const QString&);void logout();void cancel();
 void contacts();void history(const QString&);void send(const QString&,const QString&);
 bool busy()const{return pending_!=nullptr||pendingBroker_!=nullptr;}
signals:
 void busyChanged(bool);void rootUnlockRequired();
 void accountsReady(const QJsonArray&);void signedIn(const QJsonObject&);void signedOut();
 void contactsReady(const QJsonArray&);void historyReady(const QJsonArray&);
 void sent(const QJsonObject&);void failed(const QString&);
private:
 void watch(std::future<dmash::account::AccountResult>,QString kind);
 std::shared_ptr<dmash::broker::BrokerService> broker_;
 std::unique_ptr<dmash::account::AccountService> service_;
 std::unique_ptr<std::future<dmash::broker::BrokerResult>> pendingBroker_;
 QJsonObject pendingProfile_;
 QString profileDirectory_;
 std::unique_ptr<std::future<dmash::account::AccountResult>> pending_;
 QTimer poll_;QString kind_,pendingPeer_,pendingText_,operationId_;
};

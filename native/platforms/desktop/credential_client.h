#pragma once
#include <QObject>
#include <QLocalSocket>
#include <QTimer>
#include <QJsonObject>
// Credential worker owns the Account and Root; this socket owns only a UI session.
class CredentialClient final:public QObject {
 Q_OBJECT
public:
 explicit CredentialClient(QString directory,QObject* parent=nullptr);
 void request(const QString& method,const QJsonObject& params={});
 void cancel();
 bool busy()const{return !method_.isEmpty();}
signals:
 void busyChanged(bool);
 void response(const QString& method,bool ok,const QString& code,const QJsonObject& result);
private:
 void connectHost();void read();void send(const QString&,const QString&,const QJsonObject&);void fail(const QString&);
 QString directory_,method_,id_;QJsonObject params_;QLocalSocket socket_;QTimer connectTimer_,deadline_;QByteArray input_;quint32 length_=0;int attempts_=0;bool launched_=false,ready_=false;
};

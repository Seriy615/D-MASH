#pragma once
#include <QObject>
#include <QLocalSocket>
#include <QTimer>
#include <QJsonObject>
// This UI has no actor, Root codec, Account crypto or network peer dependency.
class SessionClient final : public QObject {
 Q_OBJECT
public:
 explicit SessionClient(QObject* parent=nullptr);
 ~SessionClient();
 bool attachDescriptor(int descriptor);
 void disconnectSession();
 void refresh();
 bool authenticated() const { return authenticated_; }
signals:
 void stateChanged(const QString& message, bool attached);
 void nodeStatus(const QJsonObject& status);
private:
 void send(const QString&, const QString&, const QJsonObject&);
 void fail(const QString&);
 void read();
 QLocalSocket socket_;
 QTimer timeout_;
 QByteArray input_;
 QString token_;
 qint64 generation_=0;
 quint32 length_=0;
 bool authenticated_=false;
};

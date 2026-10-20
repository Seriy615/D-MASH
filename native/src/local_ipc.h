#pragma once
#include "js_actor.h"
#include <QJsonArray>
#include <QObject>
#include <memory>
namespace dmash {
// OS-local capability transport. It never receives Root/Account secrets.
class LocalIpc final : public QObject {
  public:
    LocalIpc(JsActor&, const QString& profile, qint64 ownerGeneration, const QJsonArray& principals,
             QObject* parent = nullptr);
    ~LocalIpc();
    QJsonObject bootstrapReply() const;
    QJsonObject renewCapability(const QString& principal, qint64 ttlSeconds);
    void close();

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
// Strict UTF8, bounded object parser shared by bootstrap and framed requests.
QJsonObject parseLocalObject(const QByteArray&, qsizetype limit);
QByteArray localFrame(const QJsonObject&, qsizetype limit = 524288);
} // namespace dmash
namespace dmash {
struct BootstrapInstall {
    TransportBundle bundle;
    qint64 policyRevision = 0;
    QJsonArray principals;
    QString requestId;
};
BootstrapInstall readBootstrapInstall(qintptr fd);
} // namespace dmash

#pragma once
#include "transport_bundle.h"
#include <QJsonObject>
#include <QObject>
#include <functional>
#include <memory>
namespace dmash {
class JsActor final : public QObject {
  public:
    explicit JsActor(const QString& profile, QObject* parent = nullptr);
    ~JsActor();
    JsActor(const JsActor&) = delete;
    JsActor& operator=(const JsActor&) = delete;
    void initialize(TransportBundle&&, qint64 effectivePolicyRevision = 1);
    void openLocalSession(const QString& connectionId, bool broker);
    void closeLocalSession(const QString& connectionId);
    void dispatchLocal(const QString& connectionId, const QString& requestId, const QString& method,
                       const QJsonObject& params);
    std::function<void(const QString&, const QJsonObject&)> onLocalReply;
    QJsonObject transportPolicy();
    QJsonObject revokeTransport();
    std::function<void(const QJsonObject&)> onBootstrapFloors;
    void connectPeer(int endpointIndex);
    void queryService(int endpointIndex);
    void snapshot();
    void close();
    std::function<void(const QJsonObject&)> onEvent;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace dmash

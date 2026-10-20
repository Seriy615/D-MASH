#pragma once
#include "broker_service.h"
#include <QJsonArray>
namespace dmash::credential {
// Android supplies its separate NodeService/Binder-FD adapter; desktop spawns a child.
// Implementation retains its bootstrap lease until stop and verifies owned-process exit.
class NodeSupervisor {
  public:
    virtual ~NodeSupervisor() = default;
    virtual QJsonObject start(const broker::BrokerResult& scopedSession) = 0;
    // Existing private bootstrap MintCapability, retaining local owner contexts.
    virtual QJsonArray renewCapabilities() { return {}; }
    virtual bool running() const = 0;
    virtual void stop() = 0;
};
} // namespace dmash::credential

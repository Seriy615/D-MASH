#pragma once
#include "broker_service.h"
namespace dmash::credential {
// Android supplies its separate NodeService/Binder-FD adapter; desktop spawns a child.
// Implementation retains its bootstrap lease until stop and verifies owned-process exit.
class NodeSupervisor {
  public:
    virtual ~NodeSupervisor() = default;
    virtual QJsonObject start(const broker::BrokerResult& scopedSession) = 0;
    virtual bool running() const = 0;
    virtual void stop() = 0;
};
} // namespace dmash::credential

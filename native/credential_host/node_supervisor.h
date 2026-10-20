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
    // Worker-safe: prove exit of the previously journaled owned Node process.
    virtual bool provePreviousStopped(const broker::ControlState&, broker::RootCodec::Current) {
        return false;
    }
    // Only populated after authenticated STALE_FLOOR and verified owned-child exit.
    virtual QJsonObject takeStoppedFloors() { return {}; }
    // Private RenewCapabilityLease extends TTL without replacing contexts/tokens.
    virtual QJsonArray renewCapabilities() { return {}; }
    virtual bool running() const = 0;
    virtual void stop() = 0;
};
} // namespace dmash::credential

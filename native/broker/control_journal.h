#pragma once
#include "root_codec.h"
#include <QSqlDatabase>
#include <memory>
namespace dmash::broker {
struct ControlState {
    QString deviceId;
    quint64 generation = 0, policyRevision = 0;
    QString phase;
};
// Broker-service metadata only; no Root/PIN/Account/transport secret is stored.
// One instance belongs to one Qt worker thread. SQLite serializes distinct
// process/connection owners; UI close must not call beginFullLock().
class ControlJournal final {
  public:
    static std::unique_ptr<ControlJournal> createForProfile(const QString& path,
                                                            PreparedRoot& proof);
    static std::unique_ptr<ControlJournal> openExisting(const QString& path,
                                                        const QString& expectedDeviceId);
    ~ControlJournal();
    ControlJournal(const ControlJournal&) = delete;
    ControlJournal& operator=(const ControlJournal&) = delete;
    ControlState read();
    ControlState reserveSession(PreparedRoot& proof);
    ControlState reservePolicyRevision(quint64 expectedGeneration);
    ControlState beginFullLock();
    // Call only after daemon persisted the exact floors and acknowledged/exited,
    // or after the broker verified its owned child process actually exited.
    ControlState confirmStopped(const ControlState& pending);
    // Only after authenticated scoped-key binding AND verified owned-child
    // exit. Never accept these floors from unauthenticated errors or logs.
    ControlState mergeStoppedDaemonFloors(const ControlState& expected, quint64 minGeneration,
                                          quint64 minPolicyRevision);

  private:
    ControlJournal(const QString& path, const QString& deviceId, bool initialize);
    ControlState readRow();
    ControlState transaction(const std::function<ControlState(ControlState)>& change);
    QString connection_, deviceId_;
    QSqlDatabase db_;
};
} // namespace dmash::broker

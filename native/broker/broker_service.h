#pragma once
#include "control_journal.h"
#include "credential_store.h"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <future>
#include <mutex>
#include <thread>
namespace dmash::broker {
struct BrokerResult {
    bool ok = false, committed = false, cleanupPending = false, rootReunlockRequired = false;
    quint64 revision = 0, operationEpoch = 0;
    QString code, deviceId, accountImportPhase, accountDatabasePath;
    QJsonObject transportBundle;
    QJsonArray accountRegistry;
    QJsonObject profileInventory;
    ControlState control;
};
// Owned by credential service lifetime (not a UI window). Worker owns all roots/SQL.
// Futures contain public status or explicitly scoped Node transport bundle only.
// Callback cleanup MUST remove only legacy fast verifiers from the source profile;
// it MUST NOT delete imported Account/history databases or the original backup.
class BrokerService final {
  public:
    BrokerService(QString credentialPath, QByteArray osStorageKey, QString controlPath);
    ~BrokerService();
    std::future<BrokerResult> createProfile(QByteArray pin, QString backupPath);
    std::future<BrokerResult> sealAccountRegistry(QJsonObject publicRecord);
    std::future<BrokerResult> importProfile(QJsonObject completeProfile, QByteArray pin,
                                            QString backupPath);
    std::future<BrokerResult> unlock(QByteArray pin);
    std::future<BrokerResult> change(QByteArray oldPin, QByteArray newPin, QByteArray wipePin,
                                     std::function<bool()> cleanupLegacyVerifiers);
    std::future<BrokerResult> resumeCleanup(QByteArray pin,
                                            std::function<bool()> cleanupLegacyVerifiers);
    std::future<BrokerResult> accountImportInventory();
    std::future<BrokerResult> confirmAccountImport(PublishedAccountImport proof);
    std::future<BrokerResult> readAccountRegistry(QJsonArray encryptedRows);
    using StoppedChildProof = std::function<bool(const ControlState&, RootCodec::Current)>;
    std::future<BrokerResult> recoverStoppedTransport(StoppedChildProof);
    std::future<BrokerResult> enableNode(RootCodec::NodeSeedFactory);
    std::future<BrokerResult> transport(QJsonArray endpoints, bool directEnabled);
    // Immediate epoch fence; accepted COMMIT is reported as committed even on later cancel.
    void cancel();
    // Recheck immediately before authenticated handoff; false results must never be installed.
    bool isCurrentTransportResult(const BrokerResult& result) const;
    // Account logout/window close do not call fullRootLock/cancel; transport survives.
    std::future<BrokerResult> fullRootLock();
    // Invoke only with authenticated exact-floor daemon acknowledgement/owned-child exit proof.
    std::future<BrokerResult> confirmTransportStopped(ControlState pending);
    // Same authenticated binding/owned-child exit preconditions; handles daemon EOF floors.
    std::future<BrokerResult> mergeStoppedDaemonFloors(ControlState expected, quint64 minGeneration,
                                                       quint64 minPolicyRevision);

  private:
    std::future<BrokerResult> enqueue(std::function<BrokerResult()>);
    std::atomic<quint64> epoch_{1};
    std::atomic<bool> stopping_{false}, eraseRequested_{false};
    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<std::function<void()>> queue_;
    std::thread worker_;
    QString path_, controlPath_;
    QByteArray key_;
    std::unique_ptr<CredentialStore> store_;
    std::unique_ptr<ControlJournal> control_;
    std::unique_ptr<PreparedRoot> root_;
};
} // namespace dmash::broker

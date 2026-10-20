#pragma once
#include <QByteArray>
#include <QJsonObject>
#include <QSqlDatabase>
#include <QThread>
#include <optional>
#ifdef DMASH_JOB_FAULT_TESTS
#include <functional>
#endif
namespace dmash {
struct JobLimits {
    int globalJobs = 4096, ownerJobs = 512, destinationJobs = 128;
    qint64 globalBytes = 32 * 1024 * 1024, ownerBytes = 8 * 1024 * 1024,
           destinationBytes = 2 * 1024 * 1024;
};
// Only outer transport data enters this encrypted ledger. The OS-local adapter
// supplies an authenticated ownerScope; callers never supply SQL or key aliases.
class JobLedger final {
  public:
    JobLedger(const QString& file, const QString& nodeId, const QByteArray& storageKey,
              JobLimits limits = {});
    ~JobLedger();
    JobLedger(const JobLedger&) = delete;
    qint64 acquire(qint64 transportGeneration, qint64 policyRevision, bool enabled,
                   bool directEnabled);
    qint64 ownerGeneration() const { return generation_; }
    QJsonObject policy();
    QJsonObject bootstrapState(); // Key-authenticated floors before owner acquisition.
    bool current();
    QJsonObject revoke(qint64 expectedTransportGeneration, qint64 policyRevision);
    void setPolicy(qint64 revision, bool enabled, bool directEnabled);
    QString installDestination(const QString& ownerScope, const QByteArray& material,
                               qint64 routeGeneration, qint64 expiresAt, qint64 now);
    std::optional<QJsonObject> destination(const QString& ownerScope, const QString& handle);
    std::optional<QJsonObject> existing(const QString& ownerScope, const QString& destination,
                                        const QString& operationId, const QByteArray& opaqueBytes,
                                        qint64 expiresAt);
    QJsonObject accept(const QString& ownerScope, const QString& destination,
                       const QString& operationId, const QByteArray& opaqueBytes, qint64 expiresAt,
                       qint64 now);
    std::optional<QJsonObject> job(const QString& ownerScope, const QString& handle);
    QList<QJsonObject> due(qint64 now, int limit = 2, bool bootstrapReady = false);
    std::optional<QJsonObject> claim(const QString& handle, qint64 revision, qint64 now,
                                     bool bootstrapReady = false);
    bool defer(const QString& handle, qint64 revision, const QString& state, qint64 nextAt,
               qint64 now);
    bool finish(const QString& handle, const QString& attemptToken, const QString& state,
                qint64 nextAt, qint64 now);
    bool cancel(const QString& ownerScope, const QString& handle, qint64 now);
    bool maySend(const QString& handle, const QString& attemptToken, qint64 now);
    std::optional<qint64> nextDeadline();
    int prune(qint64 now);
    void close();
#ifdef DMASH_JOB_FAULT_TESTS
    void setTestHook(std::function<void(const char*)> hook) { hook_ = std::move(hook); }
#endif
  private:
    void check() const;
    QJsonObject metadata();
    void saveMetadata(const QJsonObject& value);
    void fence();
    QByteArray alias(const QByteArray& domain, const QList<QByteArray>& fields) const;
    QJsonObject open(const QString& domain, const QString& id, const QByteArray& iv,
                     const QByteArray& ciphertext) const;
    QPair<QByteArray, QByteArray> seal(const QString& domain, const QString& id,
                                       const QJsonObject& value) const;
    std::optional<QJsonObject> loadJob(const QString& id);
    void saveJob(QJsonObject value);
    std::optional<QJsonObject> loadDestination(const QString& id);
    void quota(const QString& ownerScope, const QString& destination, qint64 bytes);
    void hook(const char* point);
    QSqlDatabase db_;
    QString connection_, nodeId_, lastOwner_;
    QThread* thread_ = nullptr;
    QByteArray encryptionKey_, aliasKey_;
    JobLimits limits_;
    qint64 generation_ = 0;
    bool closed_ = false;
#ifdef DMASH_JOB_FAULT_TESTS
    std::function<void(const char*)> hook_;
#endif
};
} // namespace dmash

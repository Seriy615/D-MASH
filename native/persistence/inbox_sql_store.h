#pragma once
#include "../src/storage_port.h"
#include <QVector>
#ifdef DMASH_INBOX_FAULT_TESTS
#include <functional>
#endif

namespace dmash {
// Storage port for the EXISTING NodeInboxV4 encrypted-row contract. Encryption,
// Account ownership, decryption and receipt meaning remain in the JS owner.
// All methods are synchronous on the creating Qt actor thread. The dispatcher
// must validate its JS guard before calling a mutation, without an await.
class InboxSqlStore final {
  public:
    explicit InboxSqlStore(const QString& file, int maxRecords = 4096,
                           qint64 maxBytes = 32 * 1024 * 1024);
    ~InboxSqlStore();
    InboxSqlStore(const InboxSqlStore&) = delete;
    InboxSqlStore& operator=(const InboxSqlStore&) = delete;
    std::optional<EncryptedRow> read(const QString& key);
    QVector<EncryptedRow> all();
    QVector<EncryptedRow> allBindings();
    void reconcile();
    // A supplied row contributes IV/ciphertext only: key/revision are assigned
    // from the checked CAS arguments. nullopt means deletion/preserve on promote.
    bool cas(const QString& key, std::optional<qint64> revision,
             const std::optional<EncryptedRow>& row);
    bool promote(const QString& sourceKey, qint64 sourceRevision,
                 const QString& targetKey, std::optional<qint64> targetRevision,
                 const std::optional<EncryptedRow>& row);
    void close();
#ifdef DMASH_INBOX_FAULT_TESTS
    // Compiled ONLY into the separate fault-test library, never the actor port.
    void setTestHook(std::function<void(const char*)> hook) { testHook_ = std::move(hook); }
#endif

  private:
    struct Usage { qint64 count, bytes; };
    void check() const;
    Usage summary(const QString& kind);
    Usage usage(const QString& kind);
    void setUsage(const QString& kind, const Usage& totals);
    void put(const QString& key, qint64 revision, const EncryptedRow& row);
    void erase(const QString& key);
    QVector<EncryptedRow> list(const QString& kind);
    void quota(const QString& kind, const Usage& before, const Usage& after) const;
    QSqlDatabase db_;
    QString connection_;
    QThread* owner_;
    int maxRecords_;
    qint64 maxBytes_;
    bool closed_ = false;
#ifdef DMASH_INBOX_FAULT_TESTS
    std::function<void(const char*)> testHook_;
#endif
};
} // namespace dmash

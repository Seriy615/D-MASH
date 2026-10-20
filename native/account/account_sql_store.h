#pragma once
#include "../broker/account_import_proof.h"
#include <QJsonArray>
#include <QJsonObject>
#include <QSqlDatabase>
#include <functional>
#include <memory>
namespace dmash::account {
// Actual persistent backend for the narrow Account IDB transaction contract.
// One instance belongs to one Account worker; no plaintext history is accepted.
class AccountSqlStore final {
  public:
    using ImportFault = std::function<void(const QString &boundary)>;
    static std::unique_ptr<AccountSqlStore> importProfile(const QString &, const QJsonObject &,
                                                          ImportFault fault = {});
    static std::unique_ptr<AccountSqlStore> openExisting(const QString &);
    ~AccountSqlStore();
    QString sourceDigest();
    dmash::broker::PublishedAccountImport publishedImportProof();
    // Insert-only secure registry publication: duplicate identity aliases never overwrite.
    void insertRegistryRecord(const QJsonObject& row);
    bool secureRegistry();
    QJsonArray stores(const QString &database);
    void begin(const QString &database, const QStringList &stores, bool write);
    QJsonValue get(const QString &store, const QJsonValue &key);
    QJsonArray getAll(const QString &store);
    void put(const QString &store, const QJsonValue &key, const QJsonObject &row);
    void remove(const QString &store, const QJsonValue &key);
    void commit();
    void abort();

  private:
    AccountSqlStore(const QString &, bool initialize);
    void check(const QString &store, bool write = false);
    QString connection_, database_;
    QStringList stores_;
    QSqlDatabase db_;
    bool active_ = false, write_ = false;
};
} // namespace dmash::account

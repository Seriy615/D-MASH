#pragma once
#include "account_import_proof.h"
#include "root_codec.h"
#include <QSqlDatabase>
namespace dmash::broker {
struct CredentialSnapshot {
    quint64 revision;
    QJsonObject root;
    QString deviceId, importDigest;
    bool cleanupPending;
    QString accountImportPhase = "UNVERIFIED", accountDatabasePath;
};
// The owner supplies a separate OS-protected 32-byte storage key. Never link into daemon.
// One instance per worker thread; distinct owners serialize with SQLite CAS.
class CredentialStore final {
  public:
    // Package contract: version:1, inventoryComplete:true, databases:[{name,stores:
    // [{name,records:[...]}]}], root:<existing canonical encrypted row>, ancillary:<object>.
    // Inventory is an explicit exporter assertion, not a scan performed by this class.
    // Backup is encrypted and exclusive-created BEFORE the atomic import; source is untouched.
    static std::unique_ptr<CredentialStore>
    importProfile(const QString& path, const QByteArray& storageKey,
                  const QJsonObject& completePackage, PreparedRoot& proof,
                  const QString& backupPath, RootCodec::Current current);
    static QJsonObject readProfileBackup(const QString& backupPath, const QByteArray& storageKey);
    static std::unique_ptr<CredentialStore> openExisting(const QString&, const QByteArray&);
    ~CredentialStore();
    CredentialSnapshot read();
    QJsonObject exportOriginalProfile();
    CredentialSnapshot confirmAccountImport(const PublishedAccountImport&,
                                            RootCodec::Current current);
    CredentialSnapshot commitNodeEnable(const CredentialSnapshot&, const QJsonObject&,
                                        PreparedRoot&, RootCodec::Current);
    CredentialSnapshot commit(const CredentialSnapshot& expected, const QJsonObject& encryptedRoot,
                              PreparedRoot& sameIdentityProof, bool cleanupPending,
                              RootCodec::Current current);

  private:
    CredentialStore(const QString&, const QByteArray&, bool initialize);
    CredentialSnapshot readRow();
    CredentialSnapshot commitInternal(const CredentialSnapshot&, const QJsonObject&, PreparedRoot&,
                                      bool, RootCodec::Current, bool nodeEnable);

    QByteArray seal(const QByteArray&, const QByteArray& domain);
    QByteArray unseal(const QByteArray&, const QByteArray& domain);
    QString connection_;
    QByteArray key_;
    QSqlDatabase db_;
};
} // namespace dmash::broker

#pragma once
#include "../broker/account_import_proof.h"
#include "legacy_kyber.h"
#include <QJsonArray>
#include <QJsonObject>
#include <QString>
#include <functional>
#include <future>
#include <memory>
#include <optional>
namespace dmash::account {
struct AccountResult {
    bool ok = false;
    QString code;
    QJsonObject value;
    QJsonArray rows;
    std::optional<dmash::broker::PublishedAccountImport> importProof;
};
// Credential/Account owner process only. No password, master, Account KEM or
// plaintext may cross the separate Node daemon IPC boundary.
class AccountService final {
  public:
    // Transport callback runs on Account worker. It must use an authenticated
    // Account-scoped daemon connection and return actual committed responses.
    using Transport = std::function<QJsonObject(const QString &routeScope, const QString &method,
                                                const QJsonObject &params)>;
    using RegistryReader = std::function<QJsonArray(const QJsonArray &encryptedRows)>;
    using RegistryWriter = std::function<QJsonObject(const QJsonObject& publicRecord)>;
    AccountService(QString accountDatabasePath, Transport transport = {},
                   RegistryReader registryReader = {}, RegistryWriter registryWriter = {});
    ~AccountService();
    // Explicit full inventory package from CredentialStore; never overwrites a target.
    std::future<AccountResult> importProfile(QJsonObject completeProfile);
    std::future<AccountResult> verifyPublishedImport();
    std::future<AccountResult> listAccounts();
    std::future<AccountResult> createAccount(QString identity, QByteArray password,
                                             QString displayName = {});
    std::future<AccountResult> login(QString savedAccountIdentity, QByteArray accountPassword);
    std::future<AccountResult> listContacts();
    std::future<AccountResult> sync();
    std::future<AccountResult> listHistory(QString peer, int beforeSequence = 0, int limit = 50);
    std::future<AccountResult> sendText(QString peer, QString operationId, QString text);
    std::future<AccountResult> pairingCreate(QString expectedPeer = {});
    std::future<AccountResult> pairingInspect(QString signedBundle, QString expectedPeer = {});
    std::future<AccountResult> pairingRequest(QString signedBundle, QString expectedPeer);
    std::future<AccountResult> pairingOffers();
    std::future<AccountResult> pairingAdvance(QJsonObject selection);
    std::future<AccountResult> logout();
    // Root lock must call this in addition to fencing broker/daemon authority.
    void cancel();

  private:
    struct State;
    std::unique_ptr<State> state_;
};
} // namespace dmash::account

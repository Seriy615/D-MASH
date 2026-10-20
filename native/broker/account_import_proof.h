#pragma once
#include <QString>
namespace dmash::account {
class AccountSqlStore;
}
namespace dmash::broker {
// Owner-process receipt produced only by an opened, published Account store.
// This is a typed internal acknowledgement, not a network authorization/token.
class PublishedAccountImport final {
  public:
    PublishedAccountImport(const PublishedAccountImport &) = default;
    PublishedAccountImport &operator=(const PublishedAccountImport &) = default;
    QString sourceDigest() const { return digest_; }
    QString databasePath() const { return path_; }

  private:
    friend class dmash::account::AccountSqlStore;
    friend class CredentialStore;
    PublishedAccountImport(QString digest, QString path)
        : digest_(std::move(digest)), path_(std::move(path)) {}
    QString digest_, path_;
};
} // namespace dmash::broker

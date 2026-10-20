#pragma once
#include <QByteArray>
#include <QSqlDatabase>
#include <QThread>
#include <optional>
namespace dmash {
struct EncryptedRow {
    QString key;
    qint64 revision;
    QByteArray iv, ciphertext;
};
// Native implementation of the existing encrypted relationship read/CAS contract.
// No key, Account payload or SQL text crosses this adapter API.
class RelationshipSqlStore final {
  public:
    explicit RelationshipSqlStore(const QString& file);
    ~RelationshipSqlStore();
    RelationshipSqlStore(const RelationshipSqlStore&) = delete;
    RelationshipSqlStore& operator=(const RelationshipSqlStore&) = delete;
    std::optional<EncryptedRow> read(const QString& key);
    bool cas(const QString& key, std::optional<qint64> revision, const QByteArray& iv,
             const QByteArray& ciphertext, bool binding, int maxRelationships);
    void close();

  private:
    void check() const;
    QSqlDatabase db_;
    QString connection_;
    QThread* owner_;
    bool closed_ = false;
};
} // namespace dmash

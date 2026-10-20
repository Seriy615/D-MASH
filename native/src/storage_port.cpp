#include "storage_port.h"
#include <QRegularExpression>
#include <QSqlQuery>
#include <QUuid>
#include <QVariant>
#include <stdexcept>
namespace dmash {
namespace {
void require(bool ok, const char* message) {
    if (!ok)
        throw std::runtime_error(message);
}
void key(const QString& value) {
    require(value == "binding" || QRegularExpression("^[0-9a-f]{64}$").match(value).hasMatch(),
            "Invalid relationship key");
}
void sql(bool ok) { require(ok, "Native relationship transaction failed"); }
} // namespace
RelationshipSqlStore::RelationshipSqlStore(const QString& file)
    : connection_(QUuid::createUuid().toString()), owner_(QThread::currentThread()) {
    db_ = QSqlDatabase::addDatabase("QSQLITE", connection_);
    db_.setDatabaseName(file);
    try {
        sql(db_.open());
        QSqlQuery q(db_);
        sql(q.exec("PRAGMA busy_timeout=250"));
        sql(q.exec("PRAGMA journal_mode=WAL"));
        require(q.next() && q.value(0).toString().toLower() == "wal",
                "Native relationship WAL unavailable");
        sql(q.exec("PRAGMA synchronous=FULL"));
        sql(q.exec("PRAGMA synchronous"));
        require(q.next() && q.value(0).toInt() == 2, "Native relationship durability unavailable");
        sql(q.exec("CREATE TABLE IF NOT EXISTS node_relationships (key TEXT PRIMARY KEY NOT "
                   "NULL,revision INTEGER NOT NULL CHECK(revision>0),iv BLOB NOT NULL "
                   "CHECK(length(iv)=12),ciphertext BLOB NOT NULL CHECK(length(ciphertext)>=16))"));
    } catch (...) {
        close();
        throw;
    }
}
RelationshipSqlStore::~RelationshipSqlStore() { close(); }
void RelationshipSqlStore::check() const {
    require(!closed_ && owner_ == QThread::currentThread(),
            "Native relationship store owner changed");
}
std::optional<EncryptedRow> RelationshipSqlStore::read(const QString& name) {
    check();
    key(name);
    QSqlQuery q(db_);
    sql(q.prepare(
        "SELECT revision,CASE WHEN length(iv)=12 THEN iv ELSE NULL END,"
        "CASE WHEN length(ciphertext) BETWEEN 16 AND 1048576 THEN ciphertext ELSE NULL END "
        "FROM node_relationships WHERE key=?"));
    q.addBindValue(name);
    sql(q.exec());
    if (!q.next())
        return std::nullopt;
    const auto revision = q.value(0).toLongLong();
    require(revision >= 1 && revision <= 9007199254740991LL,
            "Native relationship revision invalid");
    const auto iv = q.value(1).toByteArray(), ciphertext = q.value(2).toByteArray();
    require(iv.size() == 12 && ciphertext.size() >= 16, "Native relationship envelope invalid");
    return EncryptedRow{name, revision, iv, ciphertext};
}
bool RelationshipSqlStore::cas(const QString& name, std::optional<qint64> revision,
                               const QByteArray& iv, const QByteArray& ciphertext, bool binding,
                               int maxRelationships) {
    check();
    key(name);
    require(!binding || name == "binding", "Invalid relationship binding key");
    require(maxRelationships >= 1 && maxRelationships <= 65536, "Invalid relationship quota");
    require(!revision || (*revision >= 1 && *revision < 9007199254740991LL),
            "Invalid relationship revision");
    require(iv.size() == 12 && ciphertext.size() >= 16 && ciphertext.size() <= 1024 * 1024,
            "Invalid encrypted relationship envelope");
    QSqlQuery begin(db_);
    sql(begin.exec("BEGIN IMMEDIATE"));
    bool active = true;
    try {
        const auto current = read(name);
        if ((current ? std::optional<qint64>(current->revision) : std::nullopt) != revision) {
            sql(begin.exec("ROLLBACK"));
            return false;
        }
        if (!current) {
            QSqlQuery count(db_);
            sql(count.exec("SELECT count(*) FROM node_relationships"));
            sql(count.next());
            const auto n = count.value(0).toLongLong();
            require((binding && n == 0) || (!binding && n < maxRelationships + 1),
                    binding ? "Native relationship binding has orphan rows"
                            : "Native relationship quota reached");
        }
        QSqlQuery write(db_);
        sql(write.prepare(
            "INSERT INTO node_relationships(key,revision,iv,ciphertext) VALUES(?,?,?,?) ON "
            "CONFLICT(key) DO UPDATE SET "
            "revision=excluded.revision,iv=excluded.iv,ciphertext=excluded.ciphertext"));
        write.addBindValue(name);
        write.addBindValue(revision.value_or(0) + 1);
        write.addBindValue(iv);
        write.addBindValue(ciphertext);
        sql(write.exec());
        sql(begin.exec("COMMIT"));
        active = false;
        return true;
    } catch (...) {
        if (active)
            begin.exec("ROLLBACK");
        throw;
    }
}
void RelationshipSqlStore::close() {
    if (closed_)
        return;
    closed_ = true;
    // The Qt actor must destroy all its ports before leaving the owning thread.
    Q_ASSERT(owner_ == QThread::currentThread());
    db_.close();
    db_ = QSqlDatabase();
    QSqlDatabase::removeDatabase(connection_);
}
} // namespace dmash

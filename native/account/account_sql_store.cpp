#include "account_sql_store.h"
#include "legacy_kyber.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QSqlQuery>
#include <QUuid>
#ifdef Q_OS_WIN
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif
namespace dmash::account {
namespace {
void need(bool b, const char *c = "ACCOUNT_STORE_CORRUPT") {
    if (!b)
        throw AccountError(c);
}
void sql(QSqlDatabase &d, const QString &s) {
    QSqlQuery q(d);
    need(q.exec(s), "ACCOUNT_STORE_IO_FAILED");
}
QByteArray encode(const QJsonValue &v) {
    auto b = QJsonDocument(QJsonArray{v}).toJson(QJsonDocument::Compact);
    need(b.size() <= 2 * 1024 * 1024, "ACCOUNT_RECORD_LIMIT");
    return b;
}
QJsonValue decode(const QByteArray &b) {
    need(b.size() <= 2 * 1024 * 1024, "ACCOUNT_RECORD_LIMIT");
    QJsonParseError e;
    auto a = QJsonDocument::fromJson(b, &e).array();
    need(e.error == QJsonParseError::NoError && a.size() == 1);
    return a[0];
}
void pathCheck(const QString &p) {
    QFileInfo f(p);
    need(f.isAbsolute() && !f.isSymLink() && f.dir().exists(), "ACCOUNT_PATH_REJECTED");
#ifndef Q_OS_WIN
    const auto bad = QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup |
                     QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther;
    need(!(QFileInfo(f.dir().absolutePath()).permissions() & bad), "ACCOUNT_PATH_REJECTED");
    if (f.exists())
        need(!(f.permissions() & bad), "ACCOUNT_PATH_REJECTED");
#endif
}
void publish(const QString &stage, const QString &path) {
#ifdef Q_OS_WIN
    if (!MoveFileExW(reinterpret_cast<LPCWSTR>(stage.utf16()),
                     reinterpret_cast<LPCWSTR>(path.utf16()), MOVEFILE_WRITE_THROUGH)) {
        const auto error = GetLastError();
        need(error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS,
             "ACCOUNT_IMPORT_PUBLISH_FAILED");
        throw AccountError("ACCOUNT_IMPORT_PUBLISH_RACE");
    }
#else
    const auto from = QFile::encodeName(stage), to = QFile::encodeName(path);
    int file = ::open(from.constData(), O_RDONLY);
    need(file >= 0, "ACCOUNT_IMPORT_PUBLISH_FAILED");
    const int flushed = ::fsync(file);
    ::close(file);
    need(flushed == 0, "ACCOUNT_IMPORT_PUBLISH_FAILED");
    if (::link(from.constData(), to.constData()) != 0) {
        need(errno == EEXIST, "ACCOUNT_IMPORT_PUBLISH_FAILED");
        throw AccountError("ACCOUNT_IMPORT_PUBLISH_RACE");
    }
    const auto parent = QFile::encodeName(QFileInfo(path).dir().absolutePath());
    int directory = ::open(parent.constData(), O_RDONLY | O_DIRECTORY);
    need(directory >= 0, "ACCOUNT_IMPORT_PUBLISH_FAILED");
    const int synced = ::fsync(directory);
    ::close(directory);
    need(synced == 0, "ACCOUNT_IMPORT_PUBLISH_FAILED");
    // Only the service-created staging name is removed. The accepted file and source remain.
    need(::unlink(from.constData()) == 0, "ACCOUNT_IMPORT_STAGE_CLEANUP_FAILED");
#endif
}
void removeStage(const QString &stage) {
    QFile::remove(stage);
    QFile::remove(stage + "-wal");
    QFile::remove(stage + "-shm");
}

} // namespace
AccountSqlStore::AccountSqlStore(const QString &path, bool initialize)
    : connection_("dmash-account-" + QUuid::createUuid().toString()) {
    pathCheck(path);
    need(QFileInfo::exists(path), "ACCOUNT_PROFILE_MISSING");
    db_ = QSqlDatabase::addDatabase("QSQLITE", connection_);
    db_.setDatabaseName(path);
    db_.setConnectOptions("QSQLITE_BUSY_TIMEOUT=5000");
    try {
        need(db_.open(), "ACCOUNT_STORE_UNAVAILABLE");
        sql(db_, "PRAGMA journal_mode=WAL");
        sql(db_, "PRAGMA synchronous=FULL");
        if (initialize) {
            sql(db_, "CREATE TABLE account_import(id INTEGER PRIMARY KEY CHECK(id=1),source_digest "
                     "TEXT NOT NULL,registry_mode TEXT NOT NULL CHECK(registry_mode IN "
                     "('SECURE','LEGACY')))");
            sql(db_, "CREATE TABLE account_stores(database_name TEXT NOT NULL,store_name TEXT NOT "
                     "NULL,PRIMARY KEY(database_name,store_name))");
            sql(db_, "CREATE TABLE account_rows(database_name TEXT NOT NULL,store_name TEXT NOT "
                     "NULL,key_json BLOB NOT NULL,row_json BLOB NOT NULL,PRIMARY "
                     "KEY(database_name,store_name,key_json))");
        } else {
            QSqlQuery q(db_);
            need(q.exec("SELECT source_digest FROM account_import WHERE id=1") && q.next(),
                 "ACCOUNT_PROFILE_MISSING");
        }
    } catch (...) {
        db_.close();
        db_ = QSqlDatabase();
        QSqlDatabase::removeDatabase(connection_);
        throw;
    }
}
AccountSqlStore::~AccountSqlStore() {
    if (active_)
        db_.rollback();
    db_.close();
    db_ = QSqlDatabase();
    QSqlDatabase::removeDatabase(connection_);
}
std::unique_ptr<AccountSqlStore> AccountSqlStore::openExisting(const QString &p) {
    return std::unique_ptr<AccountSqlStore>(new AccountSqlStore(p, false));
}
std::unique_ptr<AccountSqlStore>
AccountSqlStore::importProfile(const QString &path, const QJsonObject &p, ImportFault fault) {
    need(p.value("version") == 1 && p.value("inventoryComplete") == true &&
             p.value("databases").isArray() && p.value("root").isObject() &&
             !p.value("root").toObject().isEmpty(),
         "COMPLETE_PROFILE_REQUIRED");
    auto bytes = QJsonDocument(p).toJson(QJsonDocument::Compact);
    need(bytes.size() <= 64 * 1024 * 1024, "ACCOUNT_PROFILE_LIMIT");
    pathCheck(path);
    const auto digest =
        QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
    auto accepted = [&] {
        auto existing = openExisting(path);
        need(existing->sourceDigest() == digest, "ACCOUNT_PROFILE_CONFLICT");
        return existing;
    };
    if (QFileInfo::exists(path))
        return accepted();
    const auto stage = path + ".import-" + QUuid::createUuid().toString(QUuid::WithoutBraces);
    QFile f(stage);
    need(f.open(QIODevice::WriteOnly | QIODevice::NewOnly), "ACCOUNT_IMPORT_STAGE_FAILED");
    need(f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner),
         "ACCOUNT_PATH_REJECTED");
    f.close();
    std::unique_ptr<AccountSqlStore> s;
    try {
        s = std::unique_ptr<AccountSqlStore>(new AccountSqlStore(stage, true));
    } catch (...) {
        removeStage(stage);
        throw;
    }
    sql(s->db_, "BEGIN IMMEDIATE");
    try {
        bool registry = false, vault = false, secure = false;
        int count = 0;
        for (auto dv : p.value("databases").toArray()) {
            auto d = dv.toObject();
            auto db = d.value("name").toString();
            if (db != "dm_registry_v1" && db != "dm_registry_secure_v1" && db != "dm_gamma_vault")
                continue;
            registry |= db == "dm_registry_v1" || db == "dm_registry_secure_v1";
            secure |= db == "dm_registry_secure_v1";
            vault |= db == "dm_gamma_vault";
            need(d.value("stores").isArray(), "COMPLETE_PROFILE_REQUIRED");
            for (auto sv : d.value("stores").toArray()) {
                auto store = sv.toObject();
                auto name = store.value("name").toString();
                need(!name.isEmpty() && name.size() <= 256 && store.value("records").isArray(),
                     "COMPLETE_PROFILE_REQUIRED");
                QSqlQuery create(s->db_);
                create.prepare("INSERT INTO account_stores VALUES(?,?)");
                create.addBindValue(db);
                create.addBindValue(name);
                need(create.exec(), "ACCOUNT_IMPORT_CONFLICT");
                for (auto rv : store.value("records").toArray()) {
                    need(++count <= 100000, "ACCOUNT_PROFILE_LIMIT");
                    auto wrapper = rv.toObject();
                    const bool wrapped = wrapper.contains("key") && wrapper.contains("value");
                    auto row = wrapped ? wrapper.value("value").toObject() : wrapper;
                    QJsonValue key =
                        wrapped ? wrapper.value("key")
                                : row.value(name == "meta"
                                                ? "key"
                                                : (db == "dm_registry_v1" && name == "accounts"
                                                       ? "id"
                                                       : "alias"));
                    need(!row.isEmpty() && !key.isUndefined() && !key.isNull(),
                         "ACCOUNT_IMPORT_KEY_REQUIRED");
                    QSqlQuery q(s->db_);
                    q.prepare("INSERT INTO account_rows VALUES(?,?,?,?)");
                    q.addBindValue(db);
                    q.addBindValue(name);
                    q.addBindValue(encode(key));
                    q.addBindValue(encode(row));
                    need(q.exec(), "ACCOUNT_IMPORT_CONFLICT");
                }
            }
        }
        need(registry && vault, "ACCOUNT_PROFILE_INCOMPLETE");
        {
            QSqlQuery q(s->db_);
            q.prepare("INSERT INTO account_import VALUES(1,?,?)");
            q.addBindValue(QString::fromLatin1(
                QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex()));
            q.addBindValue(secure ? "SECURE" : "LEGACY");
            need(q.exec(), "ACCOUNT_STORE_IO_FAILED");
        }
        if (fault)
            fault("before-stage-commit");
        sql(s->db_, "COMMIT");
        if (fault)
            fault("after-stage-commit");
        sql(s->db_, "PRAGMA wal_checkpoint(TRUNCATE)");
        s.reset();
        try {
            publish(stage, path);
        } catch (const AccountError &e) {
            if (std::string(e.what()) != "ACCOUNT_IMPORT_PUBLISH_RACE")
                throw;
            removeStage(stage);
            return accepted();
        }
        if (fault)
            fault("after-publish");
        return openExisting(path);
    } catch (...) {
        if (s) {
            s->db_.rollback();
            s.reset();
        }
        removeStage(stage);
        throw;
    }
}
dmash::broker::PublishedAccountImport AccountSqlStore::publishedImportProof() {
    need(!active_, "ACCOUNT_TRANSACTION_BUSY");
    const QFileInfo file(db_.databaseName());
    need(file.exists() && file.isFile() && !file.isSymLink(), "ACCOUNT_PROFILE_MISSING");
    return dmash::broker::PublishedAccountImport(sourceDigest(), file.canonicalFilePath());
}
QString AccountSqlStore::sourceDigest() {
    QSqlQuery q(db_);
    need(q.exec("SELECT source_digest FROM account_import WHERE id=1") && q.next());
    const auto digest = q.value(0).toString();
    need(digest.size() == 64);
    return digest;
}
bool AccountSqlStore::secureRegistry() {
    QSqlQuery q(db_);
    need(q.exec("SELECT registry_mode FROM account_import WHERE id=1") && q.next());
    auto mode = q.value(0).toString();
    need(mode == "SECURE" || mode == "LEGACY");
    return mode == "SECURE";
}
QJsonArray AccountSqlStore::stores(const QString &db) {
    QSqlQuery q(db_);
    q.prepare("SELECT store_name FROM account_stores WHERE database_name=? ORDER BY store_name");
    q.addBindValue(db);
    need(q.exec());
    QJsonArray result;
    while (q.next())
        result.append(q.value(0).toString());
    need(!result.isEmpty(), "ACCOUNT_DATABASE_MISSING");
    return result;
}
void AccountSqlStore::begin(const QString &db, const QStringList &names, bool write) {
    need(!active_ && !names.isEmpty(), "ACCOUNT_TRANSACTION_BUSY");
    auto actual = stores(db);
    for (auto name : names)
        need(actual.contains(name), "ACCOUNT_STORE_MISSING");
    sql(db_, write ? "BEGIN IMMEDIATE" : "BEGIN");
    database_ = db;
    stores_ = names;
    write_ = write;
    active_ = true;
}
void AccountSqlStore::check(const QString &s, bool write) {
    need(active_ && stores_.contains(s) && (!write || write_), "ACCOUNT_TRANSACTION_SCOPE");
}
QJsonValue AccountSqlStore::get(const QString &s, const QJsonValue &key) {
    check(s);
    QSqlQuery q(db_);
    q.prepare(
        "SELECT row_json FROM account_rows WHERE database_name=? AND store_name=? AND key_json=?");
    q.addBindValue(database_);
    q.addBindValue(s);
    q.addBindValue(encode(key));
    need(q.exec());
    return q.next() ? decode(q.value(0).toByteArray()) : QJsonValue(QJsonValue::Null);
}
QJsonArray AccountSqlStore::getAll(const QString &s) {
    check(s);
    QSqlQuery q(db_);
    q.prepare("SELECT row_json FROM account_rows WHERE database_name=? AND store_name=? ORDER BY "
              "key_json LIMIT 100001");
    q.addBindValue(database_);
    q.addBindValue(s);
    need(q.exec());
    QJsonArray out;
    qsizetype size = 0;
    while (q.next()) {
        auto bytes = q.value(0).toByteArray();
        size += bytes.size();
        need(out.size() < 100000 && size <= 64 * 1024 * 1024, "ACCOUNT_PROFILE_LIMIT");
        out.append(decode(bytes));
    }
    return out;
}
void AccountSqlStore::put(const QString &s, const QJsonValue &key, const QJsonObject &row) {
    check(s, true);
    need(key.isString() && !row.isEmpty(), "ACCOUNT_KEY_INVALID");
    QSqlQuery q(db_);
    q.prepare(
        "INSERT INTO account_rows VALUES(?,?,?,?) ON CONFLICT(database_name,store_name,key_json) "
        "DO UPDATE SET row_json=excluded.row_json");
    q.addBindValue(database_);
    q.addBindValue(s);
    q.addBindValue(encode(key));
    q.addBindValue(encode(row));
    need(q.exec(), "ACCOUNT_STORE_IO_FAILED");
}
void AccountSqlStore::remove(const QString &s, const QJsonValue &key) {
    check(s, true);
    QSqlQuery q(db_);
    q.prepare("DELETE FROM account_rows WHERE database_name=? AND store_name=? AND key_json=?");
    q.addBindValue(database_);
    q.addBindValue(s);
    q.addBindValue(encode(key));
    need(q.exec(), "ACCOUNT_STORE_IO_FAILED");
}
void AccountSqlStore::commit() {
    need(active_, "ACCOUNT_TRANSACTION_REQUIRED");
    sql(db_, "COMMIT");
    active_ = false;
    stores_.clear();
}
void AccountSqlStore::abort() {
    if (active_)
        db_.rollback();
    active_ = false;
    stores_.clear();
}
} // namespace dmash::account

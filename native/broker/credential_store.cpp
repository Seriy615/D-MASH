#include "credential_store.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QSet>
#include <QSqlQuery>
#include <QUuid>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifdef Q_OS_WIN
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif
namespace dmash::broker {
namespace {
constexpr int MaxBlob = 64 * 1024 * 1024;
void need(bool b, const char *code = "CREDENTIAL_STORE_CORRUPT") {
    if (!b)
        throw Error(code);
}
void sql(QSqlDatabase &db, const QString &s) {
    QSqlQuery q(db);
    need(q.exec(s), "CREDENTIAL_STORE_IO_FAILED");
}
void pathCheck(const QString &path) {
    QFileInfo f(path);
    need(f.isAbsolute() && !f.isSymLink() && f.dir().exists(), "CREDENTIAL_PATH_REJECTED");
#ifndef Q_OS_WIN
    const auto bad = QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup |
                     QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther;
    need(!(QFileInfo(f.dir().absolutePath()).permissions() & bad), "CREDENTIAL_PATH_REJECTED");
    if (f.exists())
        need(!(f.permissions() & bad), "CREDENTIAL_PATH_REJECTED");
#endif
}
void exclusiveFile(const QString &path, const QByteArray &bytes) {
    pathCheck(path);
    QFile f(path);
    need(f.open(QIODevice::WriteOnly | QIODevice::NewOnly), "CREDENTIAL_FILE_EXISTS");
    need(f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner),
         "CREDENTIAL_PATH_REJECTED");
    need(f.write(bytes) == bytes.size() && f.flush(), "CREDENTIAL_BACKUP_FAILED");
#ifdef Q_OS_WIN
    need(FlushFileBuffers(reinterpret_cast<HANDLE>(_get_osfhandle(f.handle()))) != 0,
         "CREDENTIAL_BACKUP_FAILED");
#else
    need(::fsync(f.handle()) == 0, "CREDENTIAL_BACKUP_FAILED");
#endif
    f.close();
#ifndef Q_OS_WIN
    const auto parent = QFile::encodeName(QFileInfo(path).dir().absolutePath());
    const int directory = ::open(parent.constData(), O_RDONLY | O_DIRECTORY);
    need(directory >= 0, "CREDENTIAL_BACKUP_FAILED");
    const int synced = ::fsync(directory);
    ::close(directory);
    need(synced == 0, "CREDENTIAL_BACKUP_FAILED");
#endif
}
QByteArray json(const QJsonObject &o) {
    auto b = QJsonDocument(o).toJson(QJsonDocument::Compact);
    need(b.size() <= MaxBlob, "CREDENTIAL_QUOTA");
    return b;
}
QJsonObject object(const QByteArray &b) {
    QJsonParseError e;
    auto d = QJsonDocument::fromJson(b, &e);
    need(e.error == QJsonParseError::NoError && d.isObject());
    return d.object();
}
void inventory(const QJsonObject &p) {
    need(p.value("version") == 1 && p.value("inventoryComplete") == true &&
             p.value("databases").isArray() && p.value("ancillary").isObject(),
         "COMPLETE_PROFILE_REQUIRED");
    auto dbs = p.value("databases").toArray();
    need(!dbs.isEmpty() && dbs.size() <= 256, "COMPLETE_PROFILE_REQUIRED");
    QSet<QString> seen;
    int total = 0;
    for (auto v : dbs) {
        auto d = v.toObject();
        auto n = d.value("name").toString();
        need(!n.isEmpty() && n.size() <= 4096 && !seen.contains(n) && d.value("stores").isArray(),
             "COMPLETE_PROFILE_REQUIRED");
        seen.insert(n);
        QSet<QString> stores;
        for (auto sv : d.value("stores").toArray()) {
            auto s = sv.toObject();
            auto sn = s.value("name").toString();
            need(!sn.isEmpty() && sn.size() <= 4096 && !stores.contains(sn) &&
                     s.value("records").isArray(),
                 "COMPLETE_PROFILE_REQUIRED");
            stores.insert(sn);
            total += s.value("records").toArray().size();
            need(total <= 100000, "CREDENTIAL_QUOTA");
        }
    }
    need(p.value("root").isObject() && !p.value("root").toObject().isEmpty(), "ROOT_MISSING");
    json(p);
}
} // namespace
CredentialStore::CredentialStore(const QString &path, const QByteArray &key, bool initialize)
    : connection_("dmash-credential-" + QUuid::createUuid().toString()), key_(key) {
    need(key.size() == 32, "CREDENTIAL_STORAGE_KEY_REQUIRED");
    key_.detach();
    pathCheck(path);
    need(QFileInfo::exists(path), "ROOT_MISSING");
    db_ = QSqlDatabase::addDatabase("QSQLITE", connection_);
    db_.setDatabaseName(path);
    db_.setConnectOptions("QSQLITE_BUSY_TIMEOUT=5000");
    try {
        need(db_.open(), "CREDENTIAL_STORE_UNAVAILABLE");
        sql(db_, "PRAGMA journal_mode=WAL");
        sql(db_, "PRAGMA synchronous=FULL");
        if (initialize)
            sql(db_, "CREATE TABLE credentials(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER "
                     "NOT NULL,device TEXT NOT NULL,digest TEXT NOT NULL,cleanup INTEGER NOT "
                     "NULL,root BLOB NOT NULL,profile BLOB NOT NULL,account_import_phase TEXT NOT "
                     "NULL DEFAULT 'PENDING',account_database_path TEXT NOT NULL DEFAULT '')");
        else {
            // Old native stores never recorded Account publication. Missing data is
            // therefore UNVERIFIED, not permission to replay an initial snapshot.
            QSqlQuery schema(db_);
            need(schema.exec("PRAGMA table_info(credentials)"));
            bool phase = false, path = false;
            while (schema.next()) {
                phase |= schema.value(1).toString() == "account_import_phase";
                path |= schema.value(1).toString() == "account_database_path";
            }
            schema.finish();
            if (!phase || !path) {
                sql(db_, "BEGIN IMMEDIATE");
                try {
                    if (!phase)
                        sql(db_, "ALTER TABLE credentials ADD COLUMN account_import_phase TEXT NOT "
                                 "NULL DEFAULT 'UNVERIFIED'");
                    if (!path)
                        sql(db_, "ALTER TABLE credentials ADD COLUMN account_database_path TEXT "
                                 "NOT NULL DEFAULT ''");
                    sql(db_, "COMMIT");
                } catch (...) {
                    db_.rollback();
                    throw;
                }
            }
            readRow();
        }
    } catch (...) {
        db_.close();
        db_ = QSqlDatabase();
        QSqlDatabase::removeDatabase(connection_);
        OPENSSL_cleanse(key_.data(), key_.size());
        throw;
    }
}
CredentialStore::~CredentialStore() {
    db_.close();
    db_ = QSqlDatabase();
    QSqlDatabase::removeDatabase(connection_);
    OPENSSL_cleanse(key_.data(), key_.size());
}
static QByteArray sealBytes(const QByteArray &key, const QByteArray &plain,
                            const QByteArray &domain) {
    need(plain.size() <= MaxBlob, "CREDENTIAL_QUOTA");
    QByteArray iv(12, Qt::Uninitialized);
    need(RAND_bytes(reinterpret_cast<unsigned char *>(iv.data()), 12) == 1);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    need(c);
    QByteArray out(plain.size() + 16, Qt::Uninitialized);
    int n = 0, total = 0;
    bool ok = EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr,
                                 reinterpret_cast<const unsigned char *>(key.constData()),
                                 reinterpret_cast<const unsigned char *>(iv.constData())) == 1 &&
              EVP_EncryptUpdate(c, nullptr, &n,
                                reinterpret_cast<const unsigned char *>(domain.constData()),
                                domain.size()) == 1 &&
              EVP_EncryptUpdate(c, reinterpret_cast<unsigned char *>(out.data()), &n,
                                reinterpret_cast<const unsigned char *>(plain.constData()),
                                plain.size()) == 1;
    total = n;
    ok = ok &&
         EVP_EncryptFinal_ex(c, reinterpret_cast<unsigned char *>(out.data()) + total, &n) == 1;
    total += n;
    ok = ok && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out.data() + total) == 1;
    EVP_CIPHER_CTX_free(c);
    need(ok);
    out.resize(total + 16);
    return iv + out;
}
static QByteArray unsealBytes(const QByteArray &key, const QByteArray &blob,
                              const QByteArray &domain) {
    need(blob.size() >= 28 && blob.size() <= MaxBlob + 28);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    need(c);
    QByteArray out(blob.size() - 28, Qt::Uninitialized);
    int n = 0, total = 0;
    bool ok = EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr,
                                 reinterpret_cast<const unsigned char *>(key.constData()),
                                 reinterpret_cast<const unsigned char *>(blob.constData())) == 1 &&
              EVP_DecryptUpdate(c, nullptr, &n,
                                reinterpret_cast<const unsigned char *>(domain.constData()),
                                domain.size()) == 1 &&
              EVP_DecryptUpdate(c, reinterpret_cast<unsigned char *>(out.data()), &n,
                                reinterpret_cast<const unsigned char *>(blob.constData() + 12),
                                out.size()) == 1;
    total = n;
    ok = ok &&
         EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16,
                             const_cast<char *>(blob.constData() + blob.size() - 16)) == 1 &&
         EVP_DecryptFinal_ex(c, reinterpret_cast<unsigned char *>(out.data()) + total, &n) == 1;
    EVP_CIPHER_CTX_free(c);
    need(ok, "CREDENTIAL_AUTH_FAILED");
    return out;
}
QByteArray CredentialStore::seal(const QByteArray &b, const QByteArray &domain) {
    return sealBytes(key_, b, domain);
}
QByteArray CredentialStore::unseal(const QByteArray &b, const QByteArray &domain) {
    return unsealBytes(key_, b, domain);
}
QJsonObject CredentialStore::readProfileBackup(const QString &path, const QByteArray &key) {
    need(key.size() == 32, "CREDENTIAL_STORAGE_KEY_REQUIRED");
    pathCheck(path);
    QFile f(path);
    need(f.size() >= 28 && f.size() <= MaxBlob + 28 && f.open(QIODevice::ReadOnly),
         "CREDENTIAL_BACKUP_FAILED");
    auto p = object(unsealBytes(key, f.readAll(), "dmash-profile-backup/v1"));
    inventory(p);
    return p;
}
std::unique_ptr<CredentialStore>
CredentialStore::importProfile(const QString &path, const QByteArray &key, const QJsonObject &p,
                               PreparedRoot &proof, const QString &backup,
                               RootCodec::Current current) {
    need(current && current(), "CREDENTIAL_CANCELLED");
    inventory(p);
    const auto id = proof.deviceId();
    // Proof must authenticate this exact imported row; verified independently by caller's PIN open.
    need(proof.matchesRecord(p.value("root").toObject()), "CREDENTIAL_PROOF_MISMATCH");
    pathCheck(path);
    need(!QFileInfo::exists(path), "CREDENTIAL_FILE_EXISTS");
    need(path != backup, "CREDENTIAL_PATH_REJECTED");
    exclusiveFile(path, {});
    auto s = std::unique_ptr<CredentialStore>(new CredentialStore(path, key, true));
    const auto bytes = json(p),
               digest = QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex();
    exclusiveFile(backup, s->seal(bytes, "dmash-profile-backup/v1"));
    need(current(), "CREDENTIAL_CANCELLED");
    sql(s->db_, "BEGIN IMMEDIATE");
    try {
        QSqlQuery q(s->db_);
        q.prepare("INSERT INTO credentials(id,revision,device,digest,cleanup,root,profile) "
                  "VALUES(1,?,?,?,?,?,?)");
        auto root = p.value("root").toObject();
        q.addBindValue(root.value("credentialRevision").toInteger(0));
        q.addBindValue(id);
        q.addBindValue(QString::fromLatin1(digest));
        q.addBindValue(root.value("credentials").toObject().value("legacyCleanup") != "complete");
        q.addBindValue(s->seal(json(root), "dmash-canonical-root/v1"));
        q.addBindValue(s->seal(bytes, "dmash-profile-inventory/v1"));
        need(q.exec(), "CREDENTIAL_STORE_IO_FAILED");
        need(current(), "CREDENTIAL_CANCELLED");
        sql(s->db_, "COMMIT");
    } catch (...) {
        s->db_.rollback();
        throw;
    }
    return s;
}
std::unique_ptr<CredentialStore> CredentialStore::openExisting(const QString &p,
                                                               const QByteArray &k) {
    return std::unique_ptr<CredentialStore>(new CredentialStore(p, k, false));
}
CredentialSnapshot CredentialStore::readRow() {
    QSqlQuery q(db_);
    need(
        q.exec(
            "SELECT revision,device,digest,cleanup,root,account_import_phase,account_database_path "
            "FROM credentials WHERE id=1") &&
            q.next(),
        "ROOT_MISSING");
    need(q.value(4).toByteArray().size() <= MaxBlob + 28);
    auto root = object(unseal(q.value(4).toByteArray(), "dmash-canonical-root/v1"));
    auto rev = q.value(0).toLongLong();
    need(rev >= 0 && rev <= 9007199254740991LL &&
         root.value("credentialRevision").toInteger(0) == rev);
    auto id = q.value(1).toString(), digest = q.value(2).toString();
    bool cleanup = q.value(3).toBool();
    need(cleanup == (root.value("credentials").toObject().value("legacyCleanup") != "complete"));
    const auto phase = q.value(5).toString(), path = q.value(6).toString();
    need(phase == "PENDING" || phase == "COMMITTED" || phase == "UNVERIFIED");
    need(phase != "COMMITTED" || QFileInfo(path).isAbsolute());
    need(!q.next());
    return {quint64(rev), root, id, digest, cleanup, phase, path};
}
CredentialSnapshot CredentialStore::read() { return readRow(); }
QJsonObject CredentialStore::exportOriginalProfile() {
    QSqlQuery q(db_);
    need(q.exec("SELECT profile FROM credentials WHERE id=1") && q.next(), "ROOT_MISSING");
    auto bytes = unseal(q.value(0).toByteArray(), "dmash-profile-inventory/v1");
    need(QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex()) ==
         readRow().importDigest);
    return object(bytes);
}
CredentialSnapshot CredentialStore::confirmAccountImport(const PublishedAccountImport &proof,
                                                         RootCodec::Current current) {
    need(current && current(), "CREDENTIAL_CANCELLED");
    sql(db_, "BEGIN IMMEDIATE");
    try {
        auto state = readRow();
        need(state.importDigest == proof.digest_, "ACCOUNT_IMPORT_DIGEST_MISMATCH");
        need(QFileInfo(proof.path_).isAbsolute(), "ACCOUNT_IMPORT_PATH_INVALID");
        if (state.accountImportPhase == "COMMITTED")
            need(state.accountDatabasePath == proof.path_, "ACCOUNT_IMPORT_PATH_CONFLICT");
        QSqlQuery q(db_);
        q.prepare("UPDATE credentials SET account_import_phase='COMMITTED',account_database_path=? "
                  "WHERE id=1 AND digest=?");
        q.addBindValue(proof.path_);
        q.addBindValue(proof.digest_);
        need(q.exec() && q.numRowsAffected() == 1, "ACCOUNT_IMPORT_CONFLICT");
        need(current(), "CREDENTIAL_CANCELLED");
        sql(db_, "COMMIT");
        state.accountImportPhase = "COMMITTED";
        state.accountDatabasePath = proof.path_;
        return state;
    } catch (...) {
        db_.rollback();
        throw;
    }
}
CredentialSnapshot CredentialStore::commit(const CredentialSnapshot &expected,
                                           const QJsonObject &candidate, PreparedRoot &proof,
                                           bool cleanup, RootCodec::Current current) {
    need(current && current(), "CREDENTIAL_CANCELLED");
    need(proof.deviceId() == expected.deviceId && proof.matchesRecord(candidate),
         "CREDENTIAL_PROOF_MISMATCH");
    need(expected.revision < 9007199254740991ULL, "CREDENTIAL_REVISION_EXHAUSTED");
    auto root = candidate;
    root["credentialRevision"] = double(expected.revision + 1);
    need(cleanup == (root.value("credentials").toObject().value("legacyCleanup") != "complete"));
    // Credential mutation cannot alter opaque Root material/history metadata.
    auto before = expected.root, after = root;
    for (const auto &k : {"wrap", "wrapKdf", "wrapSalt", "iv", "wrappedRoot", "credentials",
                          "credentialRevision"}) {
        before.remove(k);
        after.remove(k);
    }
    need(before == after, "CREDENTIAL_MATERIAL_CHANGED");
    sql(db_, "BEGIN IMMEDIATE");
    try {
        auto actual = readRow();
        need(actual.revision == expected.revision && actual.root == expected.root &&
                 actual.deviceId == expected.deviceId,
             "CREDENTIAL_CONFLICT");
        QSqlQuery q(db_);
        q.prepare("UPDATE credentials SET revision=?,cleanup=?,root=? WHERE id=1 AND revision=?");
        q.addBindValue(qlonglong(expected.revision + 1));
        q.addBindValue(cleanup);
        q.addBindValue(seal(json(root), "dmash-canonical-root/v1"));
        q.addBindValue(qlonglong(expected.revision));
        need(q.exec() && q.numRowsAffected() == 1, "CREDENTIAL_CONFLICT");
        need(current(), "CREDENTIAL_CANCELLED");
        sql(db_, "COMMIT");
        return {expected.revision + 1,     root,    expected.deviceId,
                expected.importDigest,     cleanup, actual.accountImportPhase,
                actual.accountDatabasePath};
    } catch (...) {
        db_.rollback();
        throw;
    }
}
} // namespace dmash::broker

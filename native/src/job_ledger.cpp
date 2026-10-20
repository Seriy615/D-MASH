#include "job_ledger.h"
#include "crypto_port.h"
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSet>
#include <QSqlQuery>
#include <QUuid>
#include <QVariant>
#include <openssl/crypto.h>
#include <stdexcept>
namespace dmash {
namespace {
constexpr qint64 MaxSafe = 9007199254740991LL, Day = 86400000;
void need(bool yes) {
    if (!yes)
        throw std::runtime_error("Job ledger rejected operation");
}
void sql(bool yes) {
    if (!yes)
        throw std::runtime_error("Job ledger transaction failed");
}
bool token(const QString& s) { return QRegularExpression("^[0-9a-f]{64}$").match(s).hasMatch(); }
qint64 number(const QJsonObject& o, const char* name, qint64 minimum = 0) {
    const auto v = o.value(name);
    const double n = v.toDouble(-1);
    need(v.isDouble() && n >= minimum && n <= MaxSafe && n == qint64(n));
    return qint64(n);
}
QString text(const QJsonObject& o, const char* name) {
    const auto v = o.value(name);
    need(v.isString());
    return v.toString();
}
QByteArray frame(const QList<QByteArray>& fields) {
    QByteArray out;
    for (const auto& f : fields) {
        need(f.size() <= 196608);
        quint32 n = quint32(f.size());
        for (int i = 3; i >= 0; --i)
            out.append(char(n >> (i * 8)));
        out += f;
    }
    return out;
}
QByteArray decode(const QString& s, int maximum) {
    need(s.size() <= (maximum + 2) / 3 * 4);
    const auto b =
        QByteArray::fromBase64Encoding(s.toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
    need(bool(b) && b.decoded.size() <= maximum && QString::fromLatin1(b.decoded.toBase64()) == s);
    return b.decoded;
}
class Tx {
    QSqlDatabase db_;
    bool active_ = true;

  public:
    explicit Tx(QSqlDatabase db) : db_(db) {
        QSqlQuery q(db_);
        sql(q.exec("BEGIN IMMEDIATE"));
    }
    ~Tx() {
        if (active_) {
            QSqlQuery q(db_);
            q.exec("ROLLBACK");
        }
    }
    void commit() {
        QSqlQuery q(db_);
        sql(q.exec("COMMIT"));
        active_ = false;
    }
};
bool terminal(const QString& s) {
    return s == "TRANSPORT_SENT" || s == "CANCELLED" || s == "EXPIRED" ||
           s == "FAILED_RETRY_BUDGET";
}
} // namespace
JobLedger::JobLedger(const QString& file, const QString& nodeId, const QByteArray& storageKey,
                     JobLimits limits)
    : connection_(QUuid::createUuid().toString()), nodeId_(nodeId),
      thread_(QThread::currentThread()), limits_(limits) {
    need(token(nodeId) && storageKey.size() == 32);
    need(limits.globalJobs >= 1 && limits.globalJobs <= 4096 && limits.ownerJobs >= 1 &&
         limits.ownerJobs <= limits.globalJobs && limits.destinationJobs >= 1 &&
         limits.destinationJobs <= limits.ownerJobs && limits.globalBytes >= 1024 &&
         limits.globalBytes <= 64 * 1024 * 1024 && limits.ownerBytes >= 1 &&
         limits.ownerBytes <= limits.globalBytes && limits.destinationBytes >= 1 &&
         limits.destinationBytes <= limits.ownerBytes);
    try {
        encryptionKey_ = CryptoPort::hkdfSha256(storageKey, nodeId.toUtf8(),
                                                "D-MASH|NATIVE-JOB-LEDGER|V1|encryption", 32);
        aliasKey_ = CryptoPort::hkdfSha256(storageKey, nodeId.toUtf8(),
                                           "D-MASH|NATIVE-JOB-LEDGER|V1|alias", 32);
        db_ = QSqlDatabase::addDatabase("QSQLITE", connection_);
        db_.setDatabaseName(file);
        sql(db_.open());
        QSqlQuery q(db_);
        sql(q.exec("PRAGMA busy_timeout=250"));
        sql(q.exec("PRAGMA journal_mode=WAL"));
        need(q.next() && q.value(0).toString().toLower() == "wal");
        sql(q.exec("PRAGMA synchronous=FULL"));
        sql(q.exec("PRAGMA synchronous"));
        need(q.next() && q.value(0).toInt() == 2);
        sql(q.exec("CREATE TABLE IF NOT EXISTS native_job_meta(key TEXT PRIMARY KEY "
                   "CHECK(key='owner'),iv BLOB NOT NULL CHECK(length(iv)=12),ciphertext BLOB NOT "
                   "NULL CHECK(length(ciphertext) BETWEEN 16 AND 4096))"));
        sql(q.exec("CREATE TABLE IF NOT EXISTS native_destinations(id TEXT PRIMARY KEY "
                   "CHECK(length(id)=64),scope TEXT NOT NULL CHECK(length(scope)=64),expires_at "
                   "INTEGER NOT NULL,iv BLOB NOT NULL CHECK(length(iv)=12),ciphertext BLOB NOT "
                   "NULL CHECK(length(ciphertext) BETWEEN 16 AND 98304))"));
        sql(q.exec("CREATE TABLE IF NOT EXISTS native_jobs(id TEXT PRIMARY KEY "
                   "CHECK(length(id)=64),scope TEXT NOT NULL CHECK(length(scope)=64),destination "
                   "TEXT NOT NULL CHECK(length(destination)=64),operation TEXT UNIQUE NOT NULL "
                   "CHECK(length(operation)=64),state TEXT NOT NULL "
                   "CHECK(length(state)<=32),next_at INTEGER NOT NULL,retention INTEGER NOT "
                   "NULL,owner_generation INTEGER NOT NULL,bytes INTEGER NOT NULL CHECK(bytes "
                   "BETWEEN 1 AND 65536),iv BLOB NOT NULL CHECK(length(iv)=12),ciphertext BLOB NOT "
                   "NULL CHECK(length(ciphertext) BETWEEN 16 AND 196608))"));
        sql(q.exec("CREATE INDEX IF NOT EXISTS native_jobs_due ON native_jobs(state,next_at)"));
        // Never manufacture a new binding over orphaned accepted work.
        sql(q.exec("SELECT count(*) FROM native_job_meta"));
        need(q.next());
        if (q.value(0).toLongLong() == 0) {
            Tx tx(db_);
            sql(q.exec("SELECT count(*) FROM native_job_meta"));
            need(q.next());
            if (q.value(0).toLongLong() != 0) {
                (void)metadata();
                tx.commit();
                return;
            }
            sql(q.exec("SELECT (SELECT count(*) FROM native_jobs)+(SELECT count(*) FROM "
                       "native_destinations)"));
            need(q.next() && q.value(0).toLongLong() == 0);
            saveMetadata({{"version", 1},
                          {"nodeId", nodeId_},
                          {"ownerGeneration", 0},
                          {"transportGeneration", 0},
                          {"policyRevision", 0},
                          {"enabled", false},
                          {"directEnabled", false}});
            tx.commit();
        } else
            (void)metadata();
    } catch (...) {
        close();
        throw;
    }
}
JobLedger::~JobLedger() { close(); }
void JobLedger::check() const { need(!closed_ && thread_ == QThread::currentThread()); }
QByteArray JobLedger::alias(const QByteArray& domain, const QList<QByteArray>& fields) const {
    return CryptoPort::hmacSha256(aliasKey_, domain + frame(fields)).toHex();
}
QPair<QByteArray, QByteArray> JobLedger::seal(const QString& domain, const QString& id,
                                              const QJsonObject& value) const {
    const auto iv = CryptoPort::random(12);
    const auto raw = QJsonDocument(value).toJson(QJsonDocument::Compact);
    need(raw.size() <= 196592);
    return {iv, CryptoPort::aesGcm(true, encryptionKey_, iv,
                                   frame({"D-MASH|NATIVE-JOB-LEDGER|V1", nodeId_.toUtf8(),
                                          domain.toUtf8(), id.toUtf8()}),
                                   raw)};
}
QJsonObject JobLedger::open(const QString& domain, const QString& id, const QByteArray& iv,
                            const QByteArray& ciphertext) const {
    need(iv.size() == 12 && ciphertext.size() >= 16 && ciphertext.size() <= 196608);
    auto raw = CryptoPort::aesGcm(
        false, encryptionKey_, iv,
        frame({"D-MASH|NATIVE-JOB-LEDGER|V1", nodeId_.toUtf8(), domain.toUtf8(), id.toUtf8()}),
        ciphertext);
    QJsonParseError e;
    auto doc = QJsonDocument::fromJson(raw, &e);
    need(e.error == QJsonParseError::NoError && doc.isObject());
    return doc.object();
}
QJsonObject JobLedger::metadata() {
    check();
    QSqlQuery q(db_);
    sql(q.exec("SELECT CASE WHEN length(iv)=12 THEN iv END,CASE WHEN length(ciphertext) BETWEEN 16 "
               "AND 4096 THEN ciphertext END FROM native_job_meta WHERE key='owner'"));
    need(q.next());
    auto m = open("meta", "owner", q.value(0).toByteArray(), q.value(1).toByteArray());
    need(m.size() == 7 && number(m, "version") == 1 && text(m, "nodeId") == nodeId_ &&
         m.value("enabled").isBool() && m.value("directEnabled").isBool());
    number(m, "ownerGeneration");
    number(m, "transportGeneration");
    number(m, "policyRevision");
    return m;
}
void JobLedger::saveMetadata(const QJsonObject& m) {
    auto envelope = seal("meta", "owner", m);
    QSqlQuery q(db_);
    sql(q.prepare("INSERT INTO native_job_meta(key,iv,ciphertext) VALUES('owner',?,?) ON "
                  "CONFLICT(key) DO UPDATE SET iv=excluded.iv,ciphertext=excluded.ciphertext"));
    q.addBindValue(envelope.first);
    q.addBindValue(envelope.second);
    sql(q.exec());
}
void JobLedger::fence() {
    need(generation_ > 0 && number(metadata(), "ownerGeneration") == generation_);
}
bool JobLedger::current() {
    check();
    return generation_ > 0 && number(metadata(), "ownerGeneration") == generation_;
}
qint64 JobLedger::acquire(qint64 transportGeneration, qint64 policyRevision, bool enabled,
                          bool directEnabled) {
    check();
    need(generation_ == 0 && transportGeneration >= 1 && transportGeneration <= MaxSafe &&
         policyRevision >= 1 && policyRevision <= MaxSafe);
    Tx tx(db_);
    auto m = metadata();
    need(transportGeneration >= number(m, "transportGeneration") &&
         policyRevision >= number(m, "policyRevision"));
    if (policyRevision == number(m, "policyRevision"))
        need(enabled == m.value("enabled").toBool() &&
             directEnabled == m.value("directEnabled").toBool());
    auto g = number(m, "ownerGeneration");
    need(g < MaxSafe);
    m["ownerGeneration"] = g + 1;
    m["transportGeneration"] = transportGeneration;
    m["policyRevision"] = policyRevision;
    m["enabled"] = enabled;
    m["directEnabled"] = directEnabled;
    saveMetadata(m);
    tx.commit();
    generation_ = g + 1;
    return generation_;
}
QJsonObject JobLedger::bootstrapState() {
    need(generation_ == 0);
    const auto m = metadata();
    return {{"minTransportGeneration", m.value("transportGeneration")},
            {"minPolicyRevision", m.value("policyRevision")}};
}
QJsonObject JobLedger::policy() {
    fence();
    return metadata();
}
QJsonObject JobLedger::revoke(qint64 expected, qint64 revision) {
    check();
    Tx tx(db_);
    fence();
    auto m = metadata();
    need(expected == number(m, "transportGeneration") && expected < MaxSafe &&
         revision > number(m, "policyRevision") && revision <= MaxSafe);
    m["transportGeneration"] = expected + 1;
    m["policyRevision"] = revision;
    m["enabled"] = false;
    saveMetadata(m);
    tx.commit();
    return m;
}
void JobLedger::setPolicy(qint64 revision, bool enabled, bool directEnabled) {
    check();
    Tx tx(db_);
    fence();
    auto m = metadata();
    need(revision > number(m, "policyRevision") && revision <= MaxSafe);
    m["policyRevision"] = revision;
    m["enabled"] = enabled;
    m["directEnabled"] = directEnabled;
    saveMetadata(m);
    tx.commit();
}
void JobLedger::hook(const char* point) {
#ifdef DMASH_JOB_FAULT_TESTS
    if (hook_)
        hook_(point);
#else
    Q_UNUSED(point);
#endif
}
std::optional<QJsonObject> JobLedger::loadDestination(const QString& id) {
    need(token(id));
    QSqlQuery q(db_);
    sql(q.prepare(
        "SELECT scope,expires_at,CASE WHEN length(iv)=12 THEN iv END,CASE WHEN length(ciphertext) "
        "BETWEEN 16 AND 98304 THEN ciphertext END FROM native_destinations WHERE id=?"));
    q.addBindValue(id);
    sql(q.exec());
    if (!q.next())
        return std::nullopt;
    auto d = open("destination", id, q.value(2).toByteArray(), q.value(3).toByteArray());
    need(text(d, "id") == id && text(d, "scope") == q.value(0).toString() &&
         number(d, "expiresAt") == q.value(1).toLongLong() && number(d, "routeGeneration", 1) > 0 &&
         token(text(d, "scope")));
    decode(text(d, "material"), 32768);
    return d;
}
QString JobLedger::installDestination(const QString& ownerScope, const QByteArray& material,
                                      qint64 routeGeneration, qint64 expiresAt, qint64 now) {
    check();
    need(token(ownerScope) && !material.isEmpty() && material.size() <= 32768 &&
         routeGeneration >= 1 && routeGeneration <= MaxSafe && now >= 0 &&
         now <= MaxSafe - 8 * Day && expiresAt > now && expiresAt <= now + 7 * Day);
    const auto id = QString::fromLatin1(
        alias("destination", {ownerScope.toUtf8(), material, QByteArray::number(routeGeneration),
                              QByteArray::number(expiresAt)}));
    Tx tx(db_);
    fence();
    if (auto old = loadDestination(id)) {
        need(text(*old, "scope") == ownerScope &&
             decode(text(*old, "material"), 32768) == material);
        tx.commit();
        return id;
    }
    QSqlQuery q(db_);
    sql(q.exec("SELECT count(*) FROM native_destinations"));
    need(q.next() && q.value(0).toLongLong() < 1024);
    QJsonObject d{{"id", id},
                  {"scope", ownerScope},
                  {"routeGeneration", routeGeneration},
                  {"expiresAt", expiresAt},
                  {"material", QString::fromLatin1(material.toBase64())}};
    auto sealed = seal("destination", id, d);
    sql(q.prepare(
        "INSERT INTO native_destinations(id,scope,expires_at,iv,ciphertext) VALUES(?,?,?,?,?)"));
    q.addBindValue(id);
    q.addBindValue(ownerScope);
    q.addBindValue(expiresAt);
    q.addBindValue(sealed.first);
    q.addBindValue(sealed.second);
    sql(q.exec());
    tx.commit();
    return id;
}
std::optional<QJsonObject> JobLedger::destination(const QString& ownerScope, const QString& id) {
    fence();
    need(token(ownerScope));
    auto d = loadDestination(id);
    if (d && text(*d, "scope") != ownerScope)
        return std::nullopt;
    return d;
}
std::optional<QJsonObject> JobLedger::loadJob(const QString& id) {
    need(token(id));
    QSqlQuery q(db_);
    sql(q.prepare(
        "SELECT scope,destination,operation,state,next_at,retention,owner_generation,bytes,CASE "
        "WHEN length(iv)=12 THEN iv END,CASE WHEN length(ciphertext) BETWEEN 16 AND 196608 THEN "
        "ciphertext END FROM native_jobs WHERE id=?"));
    q.addBindValue(id);
    sql(q.exec());
    if (!q.next())
        return std::nullopt;
    auto j = open("job", id, q.value(8).toByteArray(), q.value(9).toByteArray());
    need(text(j, "id") == id && text(j, "scope") == q.value(0).toString() &&
         text(j, "destination") == q.value(1).toString() &&
         text(j, "operation") == q.value(2).toString() &&
         text(j, "state") == q.value(3).toString() &&
         number(j, "nextAt") == q.value(4).toLongLong() &&
         number(j, "retentionUntil") == q.value(5).toLongLong() &&
         number(j, "ownerGeneration", 1) == q.value(6).toLongLong());
    const auto body = decode(text(j, "body"), 65536);
    need(!body.isEmpty() && body.size() == q.value(7).toLongLong() && token(text(j, "digest")) &&
         token(text(j, "scope")) && token(text(j, "destination")) && token(text(j, "operation")));
    number(j, "revision", 1);
    number(j, "attempts");
    number(j, "expiresAt", 1);
    return j;
}
void JobLedger::saveJob(QJsonObject j) {
    const auto id = text(j, "id");
    const auto body = decode(text(j, "body"), 65536);
    auto sealed = seal("job", id, j);
    QSqlQuery q(db_);
    sql(q.prepare(
        "INSERT INTO "
        "native_jobs(id,scope,destination,operation,state,next_at,retention,owner_generation,bytes,"
        "iv,ciphertext) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
        "state=excluded.state,next_at=excluded.next_at,retention=excluded.retention,owner_"
        "generation=excluded.owner_generation,bytes=excluded.bytes,iv=excluded.iv,ciphertext="
        "excluded.ciphertext"));
    for (const auto& s :
         {id, text(j, "scope"), text(j, "destination"), text(j, "operation"), text(j, "state")})
        q.addBindValue(s);
    q.addBindValue(number(j, "nextAt"));
    q.addBindValue(number(j, "retentionUntil"));
    q.addBindValue(number(j, "ownerGeneration", 1));
    q.addBindValue(body.size());
    q.addBindValue(sealed.first);
    q.addBindValue(sealed.second);
    sql(q.exec());
}
void JobLedger::quota(const QString& scope, const QString& destination, qint64 bytes) {
    QSqlQuery owners(db_);
    sql(owners.prepare("SELECT count(DISTINCT scope),coalesce(sum(CASE WHEN scope=? THEN 1 ELSE 0 "
                       "END),0) FROM native_jobs"));
    owners.addBindValue(scope);
    sql(owners.exec());
    need(owners.next() && (owners.value(1).toLongLong() > 0 || owners.value(0).toLongLong() < 64));
    for (int kind = 0; kind < 3; ++kind) {
        QSqlQuery q(db_);
        QString statement = "SELECT count(*),coalesce(sum(bytes),0) FROM native_jobs";
        if (kind == 1)
            statement += " WHERE scope=?";
        if (kind == 2)
            statement += " WHERE destination=?";
        sql(q.prepare(statement));
        if (kind)
            q.addBindValue(kind == 1 ? scope : destination);
        sql(q.exec());
        need(q.next());
        const auto count = q.value(0).toLongLong(), used = q.value(1).toLongLong();
        need(count >= 0 && used >= 0);
        need(count < (kind == 0   ? limits_.globalJobs
                      : kind == 1 ? limits_.ownerJobs
                                  : limits_.destinationJobs) &&
             used + bytes <= (kind == 0   ? limits_.globalBytes
                              : kind == 1 ? limits_.ownerBytes
                                          : limits_.destinationBytes));
    }
}
std::optional<QJsonObject> JobLedger::existing(const QString& scope, const QString& destinationId,
                                               const QString& operationId, const QByteArray& body,
                                               qint64 expiresAt) {
    fence();
    need(token(scope) && token(destinationId) &&
         QRegularExpression("^[A-Za-z0-9._:-]{1,128}$").match(operationId).hasMatch() &&
         !body.isEmpty() && body.size() <= 65536 && expiresAt >= 1 && expiresAt <= MaxSafe - Day);
    const auto operation = QString::fromLatin1(
        alias("operation", {scope.toUtf8(), destinationId.toUtf8(), operationId.toUtf8()}));
    const auto digest = QString::fromLatin1(
        CryptoPort::sha256(frame({destinationId.toUtf8(), body, QByteArray::number(expiresAt)}))
            .toHex());
    QSqlQuery q(db_);
    sql(q.prepare("SELECT id FROM native_jobs WHERE operation=?"));
    q.addBindValue(operation);
    sql(q.exec());
    if (!q.next())
        return std::nullopt;
    auto previous = loadJob(q.value(0).toString());
    need(previous && text(*previous, "scope") == scope && text(*previous, "digest") == digest);
    return previous;
}
QJsonObject JobLedger::accept(const QString& scope, const QString& destinationId,
                              const QString& operationId, const QByteArray& body, qint64 expiresAt,
                              qint64 now) {
    check();
    need(token(scope) && token(destinationId) &&
         QRegularExpression("^[A-Za-z0-9._:-]{1,128}$").match(operationId).hasMatch() &&
         !body.isEmpty() && body.size() <= 65536 && now >= 0 && now <= MaxSafe - 8 * Day &&
         expiresAt >= 1 && expiresAt <= MaxSafe - Day);
    const auto operation = QString::fromLatin1(
        alias("operation", {scope.toUtf8(), destinationId.toUtf8(), operationId.toUtf8()}));
    const auto digest = QString::fromLatin1(
        CryptoPort::sha256(frame({destinationId.toUtf8(), body, QByteArray::number(expiresAt)}))
            .toHex());
    Tx tx(db_);
    fence();
    QSqlQuery q(db_);
    sql(q.prepare("SELECT id FROM native_jobs WHERE operation=?"));
    q.addBindValue(operation);
    sql(q.exec());
    if (q.next()) {
        auto previous = loadJob(q.value(0).toString());
        need(previous && text(*previous, "scope") == scope && text(*previous, "digest") == digest);
        tx.commit();
        return *previous;
    }
    need(expiresAt > now && expiresAt <= now + 7 * Day);
    auto d = loadDestination(destinationId);
    need(d && text(*d, "scope") == scope && number(*d, "expiresAt") >= expiresAt);
    quota(scope, destinationId, body.size());
    const auto id = QString::fromLatin1(CryptoPort::random(32).toHex());
    auto p = metadata();
    QJsonObject j{{"id", id},
                  {"scope", scope},
                  {"destination", destinationId},
                  {"operation", operation},
                  {"digest", digest},
                  {"body", QString::fromLatin1(body.toBase64())},
                  {"state", p.value("enabled").toBool() ? "ACCEPTED" : "BLOCKED_POLICY"},
                  {"createdAt", now},
                  {"expiresAt", expiresAt},
                  {"retentionUntil", expiresAt + Day},
                  {"nextAt", now},
                  {"ownerGeneration", generation_},
                  {"revision", 1},
                  {"attempts", 0},
                  {"attemptToken", QString()}};
    saveJob(j);
    hook("accept-before-commit");
    tx.commit();
    hook("accept-after-commit");
    return j;
}
std::optional<QJsonObject> JobLedger::job(const QString& scope, const QString& id) {
    fence();
    need(token(scope));
    auto j = loadJob(id);
    if (j && text(*j, "scope") != scope)
        return std::nullopt;
    return j;
}
QList<QJsonObject> JobLedger::due(qint64 now, int limit, bool bootstrapReady) {
    fence();
    need(now >= 0 && limit >= 1 && limit <= 4);
    const bool enabled = metadata().value("enabled").toBool();
    QSqlQuery owners(db_);
    sql(owners.prepare(
        QString("SELECT DISTINCT scope FROM native_jobs WHERE state NOT IN "
                "('TRANSPORT_SENT','CANCELLED','EXPIRED','FAILED_RETRY_BUDGET') AND "
                "(next_at<=? OR owner_generation<>? OR (? AND state='WAITING_BOOTSTRAP'))") +
        (enabled ? QString() : QString(" AND retention<=?")) + " ORDER BY scope LIMIT 65"));
    owners.addBindValue(now);
    owners.addBindValue(generation_);
    owners.addBindValue(bootstrapReady);
    if (!enabled)
        owners.addBindValue(now + Day);
    sql(owners.exec());
    QStringList scopes;
    while (owners.next())
        scopes << owners.value(0).toString();
    need(scopes.size() <= 64);
    int start = 0;
    if (!lastOwner_.isEmpty()) {
        while (start < scopes.size() && scopes[start] <= lastOwner_)
            ++start;
        if (start == scopes.size())
            start = 0;
    }
    QList<QJsonObject> result;
    QSet<QString> destinations;
    for (int offset = 0; offset < scopes.size() && result.size() < limit; ++offset) {
        const auto scope = scopes[(start + offset) % scopes.size()];
        QSqlQuery q(db_);
        sql(q.prepare(
            QString("SELECT id FROM native_jobs WHERE scope=? AND state NOT IN "
                    "('TRANSPORT_SENT','CANCELLED','EXPIRED','FAILED_RETRY_BUDGET') AND "
                    "(next_at<=? OR owner_generation<>? OR (? AND state='WAITING_BOOTSTRAP'))") +
            (enabled ? QString() : QString(" AND retention<=?")) + " ORDER BY next_at,id LIMIT 4"));
        q.addBindValue(scope);
        q.addBindValue(now);
        q.addBindValue(generation_);
        q.addBindValue(bootstrapReady);
        if (!enabled)
            q.addBindValue(now + Day);
        sql(q.exec());
        while (q.next()) {
            auto j = loadJob(q.value(0).toString());
            need(j.has_value());
            if (!enabled && number(*j, "expiresAt") > now)
                continue;
            if (destinations.contains(text(*j, "destination")))
                continue;
            destinations.insert(text(*j, "destination"));
            result << *j;
            lastOwner_ = scope;
            break;
        }
    }
    return result;
}
std::optional<QJsonObject> JobLedger::claim(const QString& id, qint64 revision, qint64 now,
                                            bool bootstrapReady) {
    check();
    need(now >= 0 && now <= MaxSafe - 8 * Day && revision >= 1);
    Tx tx(db_);
    fence();
    auto j = loadJob(id);
    if (!j || number(*j, "revision", 1) != revision || terminal(text(*j, "state"))) {
        tx.commit();
        return std::nullopt;
    }
    if (number(*j, "expiresAt") <= now || number(*j, "attempts") >= 20) {
        (*j)["state"] = number(*j, "expiresAt") <= now ? "EXPIRED" : "FAILED_RETRY_BUDGET";
        (*j)["nextAt"] = 0;
    } else if (!metadata().value("enabled").toBool()) {
        (*j)["state"] = "BLOCKED_POLICY";
        (*j)["nextAt"] = now;
    } else {
        need(number(*j, "ownerGeneration") != generation_ || number(*j, "nextAt") <= now ||
             (bootstrapReady && text(*j, "state") == "WAITING_BOOTSTRAP"));
        (*j)["state"] = "IN_FLIGHT";
        (*j)["attempts"] = number(*j, "attempts") + 1;
        (*j)["attemptToken"] = QString::fromLatin1(CryptoPort::random(32).toHex());
        (*j)["nextAt"] = now + 45000;
    }
    (*j)["ownerGeneration"] = generation_;
    (*j)["revision"] = revision + 1;
    saveJob(*j);
    tx.commit();
    return text(*j, "state") == "IN_FLIGHT" ? j : std::nullopt;
}
bool JobLedger::defer(const QString& id, qint64 revision, const QString& state, qint64 nextAt,
                      qint64 now) {
    check();
    need(state == "WAITING_BOOTSTRAP" || state == "WAITING_PATH" || state == "BLOCKED_POLICY");
    need(now >= 0 && now <= MaxSafe - 8 * Day && nextAt >= now && nextAt <= MaxSafe);
    Tx tx(db_);
    fence();
    auto j = loadJob(id);
    if (!j || number(*j, "revision", 1) != revision || terminal(text(*j, "state"))) {
        tx.commit();
        return false;
    }
    need(state == "WAITING_BOOTSTRAP" ? nextAt <= number(*j, "expiresAt") && nextAt <= now + 7 * Day
                                      : nextAt <= now + 60000);
    (*j)["state"] = number(*j, "expiresAt") <= now ? "EXPIRED" : state;
    (*j)["nextAt"] = nextAt;
    (*j)["attemptToken"] = QString();
    (*j)["ownerGeneration"] = generation_;
    (*j)["revision"] = revision + 1;
    saveJob(*j);
    tx.commit();
    return true;
}
bool JobLedger::finish(const QString& id, const QString& attemptToken, const QString& state,
                       qint64 nextAt, qint64 now) {
    check();
    need(token(attemptToken) &&
         (state == "TRANSPORT_SENT" || state == "WAITING_PATH" || state == "BLOCKED_POLICY") &&
         now >= 0 && nextAt >= 0 && nextAt <= MaxSafe);
    Tx tx(db_);
    fence();
    auto j = loadJob(id);
    if (!j || text(*j, "state") != "IN_FLIGHT" || text(*j, "attemptToken") != attemptToken ||
        number(*j, "ownerGeneration") != generation_) {
        tx.commit();
        return false;
    }
    (*j)["state"] = number(*j, "expiresAt") <= now ? "EXPIRED" : state;
    (*j)["nextAt"] = state == "TRANSPORT_SENT" ? 0 : nextAt;
    (*j)["attemptToken"] = QString();
    (*j)["revision"] = number(*j, "revision", 1) + 1;
    saveJob(*j);
    hook("finish-before-commit");
    tx.commit();
    hook("finish-after-commit");
    return true;
}
bool JobLedger::cancel(const QString& scope, const QString& id, qint64 now) {
    check();
    need(token(scope) && now >= 0);
    Tx tx(db_);
    fence();
    auto j = loadJob(id);
    if (!j || text(*j, "scope") != scope) {
        tx.commit();
        return false;
    }
    if (text(*j, "state") == "CANCELLED") {
        tx.commit();
        return true;
    }
    if (terminal(text(*j, "state"))) {
        tx.commit();
        return false;
    }
    (*j)["state"] = "CANCELLED";
    (*j)["nextAt"] = 0;
    (*j)["attemptToken"] = QString();
    (*j)["revision"] = number(*j, "revision", 1) + 1;
    (*j)["ownerGeneration"] = generation_;
    saveJob(*j);
    tx.commit();
    return true;
}
bool JobLedger::maySend(const QString& id, const QString& attemptToken, qint64 now) {
    fence();
    need(token(attemptToken) && now >= 0);
    if (!metadata().value("enabled").toBool())
        return false;
    auto j = loadJob(id);
    if (!j || text(*j, "state") != "IN_FLIGHT" || text(*j, "attemptToken") != attemptToken ||
        number(*j, "ownerGeneration") != generation_ || number(*j, "expiresAt") <= now)
        return false;
    auto d = loadDestination(text(*j, "destination"));
    return d && number(*d, "expiresAt") > now && text(*d, "scope") == text(*j, "scope");
}
std::optional<qint64> JobLedger::nextDeadline() {
    fence();
    const bool enabled = metadata().value("enabled").toBool();
    QSqlQuery q(db_);
    const QString jobDeadline =
        enabled
            ? "CASE WHEN state IN ('TRANSPORT_SENT','CANCELLED','EXPIRED','FAILED_RETRY_BUDGET') "
              "THEN min(9007199254740991,retention+1) WHEN owner_generation<>" +
                  QString::number(generation_) + " THEN 0 ELSE min(next_at,retention-86400000) END"
            : "CASE WHEN state IN ('TRANSPORT_SENT','CANCELLED','EXPIRED','FAILED_RETRY_BUDGET') "
              "THEN min(9007199254740991,retention+1) ELSE retention-86400000 END";
    sql(q.exec("SELECT min(deadline) FROM (SELECT min(" + jobDeadline +
               ") AS deadline FROM native_jobs UNION ALL SELECT "
               "min(min(9007199254740991,expires_at+86400001)) FROM native_destinations WHERE NOT "
               "EXISTS(SELECT 1 FROM native_jobs WHERE destination=native_destinations.id))"));
    need(q.next());
    if (q.value(0).isNull())
        return std::nullopt;
    auto deadline = q.value(0).toLongLong();
    need(deadline >= 0 && deadline <= MaxSafe);
    return deadline;
}
int JobLedger::prune(qint64 now) {
    check();
    need(now >= 0 && now <= MaxSafe);
    Tx tx(db_);
    fence();
    QSqlQuery q(db_);
    sql(q.prepare("SELECT id FROM native_jobs WHERE retention<? LIMIT 4097"));
    q.addBindValue(now);
    sql(q.exec());
    QStringList ids;
    while (q.next())
        ids << q.value(0).toString();
    need(ids.size() <= 4096);
    for (const auto& id : ids) {
        auto j = loadJob(id);
        need(j && number(*j, "retentionUntil") < now);
        QSqlQuery remove(db_);
        sql(remove.prepare("DELETE FROM native_jobs WHERE id=?"));
        remove.addBindValue(id);
        sql(remove.exec());
    }
    sql(q.prepare("DELETE FROM native_destinations WHERE expires_at<? AND NOT EXISTS(SELECT 1 FROM "
                  "native_jobs WHERE destination=native_destinations.id)"));
    q.addBindValue(now - Day);
    sql(q.exec());
    tx.commit();
    return ids.size();
}
void JobLedger::close() {
    if (closed_)
        return;
    need(thread_ == QThread::currentThread());
    closed_ = true;
    if (db_.isValid()) {
        db_.close();
        db_ = QSqlDatabase();
        QSqlDatabase::removeDatabase(connection_);
    }
    for (auto* bytes : {&encryptionKey_, &aliasKey_}) {
        if (!bytes->isEmpty())
            OPENSSL_cleanse(bytes->data(), size_t(bytes->size()));
        bytes->clear();
    }
}
} // namespace dmash

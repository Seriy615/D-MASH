#include "inbox_sql_store.h"
#include <QRegularExpression>
#include <QSqlQuery>
#include <QUuid>
#include <QVariant>
#include <stdexcept>

namespace dmash {
namespace {
constexpr qint64 MAX_REVISION = 9007199254740991LL;
constexpr qint64 HARD_RECORDS = 16384, HARD_BYTES = 64 * 1024 * 1024;
constexpr qint64 BINDINGS = 33, BINDING_BYTES = 256 * 1024;
void require(bool yes, const char* text) { if (!yes) throw std::runtime_error(text); }
void sql(bool yes) { require(yes, "Native Inbox transaction failed"); }
bool token(const QString& value) {
    return QRegularExpression("^[0-9a-f]{64}$").match(value).hasMatch();
}
void key(const QString& value) {
    require(value == "owner" || token(value) ||
                (value.startsWith("binding:") && token(value.mid(8))),
            "Invalid Inbox key");
}
QString bucket(const QString& value) {
    return value == "owner" || value.startsWith("binding:") ? "bindings" : "records";
}
void revision(std::optional<qint64> value, bool increment) {
    require(!value || (*value >= 1 && *value <= MAX_REVISION - (increment ? 1 : 0)),
            "Invalid Inbox revision");
}
void envelope(const EncryptedRow& row) {
    require(row.iv.size() == 12 && row.ciphertext.size() >= 16 &&
                row.ciphertext.size() <= 65536, "Invalid Inbox encrypted envelope");
}
qint64 size(const EncryptedRow& row) { return row.ciphertext.size() + 128; }
// Always rolls back on exceptions, including SQLite trigger/disk failures.
class Transaction {
  public:
    explicit Transaction(QSqlDatabase& db) : q_(db) { sql(q_.exec("BEGIN IMMEDIATE")); }
    ~Transaction() { if (active_) q_.exec("ROLLBACK"); }
    void commit() { sql(q_.exec("COMMIT")); active_ = false; }
  private:
    QSqlQuery q_;
    bool active_ = true;
};
EncryptedRow rowFromQuery(const QSqlQuery& q) {
    // SQL masks invalid-sized blobs BEFORE QVariant/QByteArray materialization.
    EncryptedRow row{q.value(0).toString(), q.value(1).toLongLong(),
                     q.value(2).toByteArray(), q.value(3).toByteArray()};
    key(row.key); revision(row.revision, false); envelope(row);
    return row;
}
constexpr auto SELECT_ROW =
    "SELECT key,revision,CASE WHEN length(iv)=12 THEN iv ELSE NULL END,"
    "CASE WHEN length(ciphertext) BETWEEN 16 AND 65536 THEN ciphertext ELSE NULL END "
    "FROM node_inbox_rows ";
} // namespace

InboxSqlStore::InboxSqlStore(const QString& file, int maxRecords, qint64 maxBytes)
    : connection_(QUuid::createUuid().toString()), owner_(QThread::currentThread()),
      maxRecords_(maxRecords), maxBytes_(maxBytes) {
    require(maxRecords >= 1 && maxRecords <= HARD_RECORDS && maxBytes >= 1024 &&
                maxBytes <= HARD_BYTES, "Invalid Inbox quota");
    db_ = QSqlDatabase::addDatabase("QSQLITE", connection_);
    db_.setDatabaseName(file);
    try {
        sql(db_.open()); QSqlQuery q(db_);
        sql(q.exec("PRAGMA busy_timeout=250"));
        sql(q.exec("PRAGMA journal_mode=WAL"));
        require(q.next() && q.value(0).toString().toLower() == "wal", "Native Inbox WAL unavailable");
        sql(q.exec("PRAGMA synchronous=FULL")); sql(q.exec("PRAGMA synchronous"));
        require(q.next() && q.value(0).toInt() == 2, "Native Inbox durability unavailable");
        Transaction tx(db_);
        sql(q.exec("CREATE TABLE IF NOT EXISTS node_inbox_meta (id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL)"));
        sql(q.exec("INSERT OR IGNORE INTO node_inbox_meta VALUES(1,1)"));
        sql(q.exec("SELECT version FROM node_inbox_meta WHERE id=1"));
        require(q.next() && q.value(0).toInt() == 1 && !q.next(), "Unknown Inbox schema");
        sql(q.exec("CREATE TABLE IF NOT EXISTS node_inbox_rows (key TEXT PRIMARY KEY NOT NULL,bucket TEXT NOT NULL CHECK(bucket IN ('records','bindings')),revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision BETWEEN 1 AND 9007199254740991),iv BLOB NOT NULL CHECK(typeof(iv)='blob' AND length(iv)=12),ciphertext BLOB NOT NULL CHECK(typeof(ciphertext)='blob' AND length(ciphertext) BETWEEN 16 AND 65536))"));
        sql(q.exec("CREATE INDEX IF NOT EXISTS node_inbox_bucket ON node_inbox_rows(bucket,key)"));
        sql(q.exec("CREATE TABLE IF NOT EXISTS node_inbox_usage (bucket TEXT PRIMARY KEY CHECK(bucket IN ('records','bindings')),count INTEGER NOT NULL CHECK(count>=0),bytes INTEGER NOT NULL CHECK(bytes>=0))"));
        sql(q.exec("INSERT OR IGNORE INTO node_inbox_usage VALUES('records',0,0),('bindings',0,0)"));
        tx.commit();
    } catch (...) { close(); throw; }
}
InboxSqlStore::~InboxSqlStore() { close(); }
void InboxSqlStore::check() const {
    require(!closed_ && owner_ == QThread::currentThread(), "Native Inbox store owner changed");
}
InboxSqlStore::Usage InboxSqlStore::summary(const QString& kind) {
    check(); QSqlQuery q(db_);
    sql(q.prepare("SELECT count(*),coalesce(sum(length(ciphertext)+128),0),coalesce(sum(CASE WHEN typeof(revision)!='integer' OR revision NOT BETWEEN 1 AND 9007199254740991 OR typeof(iv)!='blob' OR length(iv)!=12 OR typeof(ciphertext)!='blob' OR length(ciphertext) NOT BETWEEN 16 AND 65536 OR (bucket='records' AND (length(key)!=64 OR key GLOB '*[^0-9a-f]*')) OR (bucket='bindings' AND key!='owner' AND (length(key)!=72 OR substr(key,1,8)!='binding:' OR substr(key,9) GLOB '*[^0-9a-f]*')) THEN 1 ELSE 0 END),0) FROM node_inbox_rows WHERE bucket=?"));
    q.addBindValue(kind); sql(q.exec()); sql(q.next());
    const Usage totals{q.value(0).toLongLong(), q.value(1).toLongLong()};
    require(q.value(2).toLongLong() == 0 && totals.count >= 0 && totals.bytes >= 0 &&
                totals.count <= (kind == "bindings" ? BINDINGS : HARD_RECORDS) &&
                totals.bytes <= (kind == "bindings" ? BINDING_BYTES : HARD_BYTES),
            "Invalid Inbox persisted bounds");
    return totals;
}
InboxSqlStore::Usage InboxSqlStore::usage(const QString& kind) {
    const auto actual = summary(kind); QSqlQuery q(db_);
    sql(q.prepare("SELECT count,bytes,typeof(count),typeof(bytes) FROM node_inbox_usage WHERE bucket=?"));
    q.addBindValue(kind); sql(q.exec());
    require(q.next() && q.value(2).toString() == "integer" && q.value(3).toString() == "integer" &&
                q.value(0).toLongLong() == actual.count && q.value(1).toLongLong() == actual.bytes,
            "Inbox quota metadata missing or inconsistent");
    return actual;
}
void InboxSqlStore::setUsage(const QString& kind, const Usage& totals) {
    QSqlQuery q(db_); sql(q.prepare("INSERT INTO node_inbox_usage(bucket,count,bytes) VALUES(?,?,?) ON CONFLICT(bucket) DO UPDATE SET count=excluded.count,bytes=excluded.bytes"));
    q.addBindValue(kind); q.addBindValue(totals.count); q.addBindValue(totals.bytes); sql(q.exec());
}
void InboxSqlStore::reconcile() {
    check(); Transaction tx(db_);
    for (const auto& kind : {QString("records"), QString("bindings")}) setUsage(kind, summary(kind));
    tx.commit();
}
std::optional<EncryptedRow> InboxSqlStore::read(const QString& name) {
    check(); key(name); QSqlQuery q(db_);
    sql(q.prepare(QString(SELECT_ROW) + "WHERE key=?")); q.addBindValue(name); sql(q.exec());
    if (!q.next()) return std::nullopt;
    return rowFromQuery(q);
}
QVector<EncryptedRow> InboxSqlStore::list(const QString& kind) {
    check();
    // One transaction binds preflight totals to the fetched snapshot. Even a
    // second SQLite connection cannot add rows between check and materialize.
    Transaction tx(db_); const auto totals = summary(kind); QSqlQuery q(db_);
    sql(q.prepare(QString(SELECT_ROW) + "WHERE bucket=? ORDER BY key LIMIT ?"));
    q.addBindValue(kind); q.addBindValue(totals.count + 1); sql(q.exec());
    QVector<EncryptedRow> rows; rows.reserve(int(totals.count));
    while (q.next()) { require(rows.size() < totals.count, "Inbox snapshot changed"); rows.push_back(rowFromQuery(q)); }
    require(rows.size() == totals.count, "Inbox snapshot changed"); tx.commit(); return rows;
}
QVector<EncryptedRow> InboxSqlStore::all() { return list("records"); }
QVector<EncryptedRow> InboxSqlStore::allBindings() { return list("bindings"); }
void InboxSqlStore::quota(const QString& kind, const Usage& before, const Usage& after) const {
    const auto count = kind == "bindings" ? BINDINGS : maxRecords_;
    const auto bytes = kind == "bindings" ? BINDING_BYTES : maxBytes_;
    require(after.count >= 0 && after.bytes >= 0 &&
                !(after.count > count && after.count > before.count) &&
                !(after.bytes > bytes && after.bytes > before.bytes), "Node Inbox quota reached");
}
void InboxSqlStore::put(const QString& name, qint64 rev, const EncryptedRow& row) {
    QSqlQuery q(db_); sql(q.prepare("INSERT INTO node_inbox_rows(key,bucket,revision,iv,ciphertext) VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET bucket=excluded.bucket,revision=excluded.revision,iv=excluded.iv,ciphertext=excluded.ciphertext"));
    q.addBindValue(name); q.addBindValue(bucket(name)); q.addBindValue(rev); q.addBindValue(row.iv); q.addBindValue(row.ciphertext); sql(q.exec());
}
void InboxSqlStore::erase(const QString& name) {
    QSqlQuery q(db_); sql(q.prepare("DELETE FROM node_inbox_rows WHERE key=?")); q.addBindValue(name); sql(q.exec());
}
bool InboxSqlStore::cas(const QString& name, std::optional<qint64> rev,
                        const std::optional<EncryptedRow>& row) {
    check(); key(name); revision(rev, bool(row)); if (row) envelope(*row);
    Transaction tx(db_); const auto current = read(name);
    if ((current ? std::optional<qint64>(current->revision) : std::nullopt) != rev || (!row && !current)) return false;
    const auto kind = bucket(name);
    const auto before = usage(kind);
    if (name == "owner" && !current) {
        require(before.count == 0 && summary("records").count == 0, "Inbox owner missing");
    }
    const Usage after{before.count + (row ? (current ? 0 : 1) : -1),
                      before.bytes - (current ? size(*current) : 0) + (row ? size(*row) : 0)};
    quota(kind, before, after);
    if (row) put(name, rev.value_or(0) + 1, *row); else erase(name);
#ifdef DMASH_INBOX_FAULT_TESTS
    if (testHook_) testHook_("cas_after_row");
#endif
    setUsage(kind, after); tx.commit(); return true;
}
bool InboxSqlStore::promote(const QString& sourceKey, qint64 sourceRevision,
                            const QString& targetKey, std::optional<qint64> targetRevision,
                            const std::optional<EncryptedRow>& row) {
    check(); require(token(sourceKey) && token(targetKey) && sourceKey != targetKey, "Invalid Inbox promotion");
    revision(sourceRevision, false); revision(targetRevision, bool(row)); if (row) envelope(*row);
    Transaction tx(db_); const auto source = read(sourceKey), target = read(targetKey);
    if (!source || source->revision != sourceRevision ||
            (target ? std::optional<qint64>(target->revision) : std::nullopt) != targetRevision) return false;
    const auto before = usage("records");
    require(row || target, "Missing Inbox promotion target");
    const auto& next = row ? *row : *target;
    const Usage after{before.count - (target ? 1 : 0),
                      before.bytes - size(*source) - (target ? size(*target) : 0) + size(next)};
    quota("records", before, after);
    if (row) put(targetKey, targetRevision.value_or(0) + 1, *row);
#ifdef DMASH_INBOX_FAULT_TESTS
    if (testHook_) testHook_("promote_after_target");
#endif
    erase(sourceKey); setUsage("records", after); tx.commit(); return true;
}
void InboxSqlStore::close() {
    if (closed_) return;
    Q_ASSERT(owner_ == QThread::currentThread()); closed_ = true;
    db_.close(); db_ = QSqlDatabase(); QSqlDatabase::removeDatabase(connection_);
}
} // namespace dmash

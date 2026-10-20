#include "control_journal.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSqlQuery>
#include <QUuid>
#include <algorithm>
namespace dmash::broker {
namespace {
constexpr quint64 Maximum = 9007199254740991ULL;
void need(bool ok, const char* code = "CONTROL_STORE_CORRUPT") {
    if (!ok)
        throw Error(code);
}
void execute(QSqlDatabase& db, const QString& sql) {
    QSqlQuery q(db);
    need(q.exec(sql), "CONTROL_STORE_IO_FAILED");
}
void validId(const QString& id) {
    need(QRegularExpression("^d1_[A-Za-z0-9_-]{43}$").match(id).hasMatch(),
         "CONTROL_BINDING_INVALID");
}
void privatePath(const QString& path) {
    const QFileInfo f(path);
    need(f.isAbsolute() && !f.isSymLink(), "CONTROL_PATH_REJECTED");
    const auto parent = f.dir();
    need(parent.exists(), "CONTROL_PATH_REJECTED");
#ifndef Q_OS_WIN
    const auto p = QFileInfo(parent.path()).permissions();
    need(!(p & (QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup |
                QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther)),
         "CONTROL_PATH_REJECTED");
#endif
}
} // namespace
ControlJournal::ControlJournal(const QString& path, const QString& id, bool initialize)
    : connection_("dmash-broker-control-" + QUuid::createUuid().toString(QUuid::WithoutBraces)),
      deviceId_(id) {
    validId(id);
    privatePath(path);
    need(QFileInfo::exists(path), "CONTROL_STORE_MISSING");
#ifndef Q_OS_WIN
    const auto p = QFileInfo(path).permissions();
    need(!(p & (QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ReadOther |
                QFileDevice::WriteOther)),
         "CONTROL_PATH_REJECTED");
#endif
    db_ = QSqlDatabase::addDatabase("QSQLITE", connection_);
    db_.setDatabaseName(path);
    db_.setConnectOptions("QSQLITE_BUSY_TIMEOUT=5000");
    try {
        need(db_.open(), "CONTROL_STORE_UNAVAILABLE");
        if (initialize) {
            execute(db_, "PRAGMA journal_mode=WAL");
            execute(db_, "PRAGMA synchronous=FULL");
            execute(db_, "BEGIN IMMEDIATE");
            try {
                execute(db_,
                        "CREATE TABLE broker_control(singleton INTEGER PRIMARY KEY "
                        "CHECK(singleton=1),version INTEGER NOT NULL CHECK(version=1),device_id "
                        "TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>=0 AND "
                        "generation<=9007199254740991),policy_revision INTEGER NOT NULL "
                        "CHECK(policy_revision>=0 AND policy_revision<=9007199254740991),phase "
                        "TEXT NOT NULL CHECK(phase IN ('LOCKED','ACTIVE','REVOKING')))");
                QSqlQuery q(db_);
                q.prepare("INSERT INTO broker_control VALUES(1,1,?,0,0,'LOCKED')");
                q.addBindValue(id);
                need(q.exec(), "CONTROL_STORE_IO_FAILED");
                execute(db_, "PRAGMA user_version=1");
                execute(db_, "COMMIT");
            } catch (...) {
                db_.rollback();
                throw;
            }
        } else {
            QSqlQuery q(db_);
            need(q.exec("PRAGMA user_version") && q.next() && q.value(0).toInt() == 1);
            need(q.exec("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE "
                        "'sqlite_%'") &&
                 q.next() && q.value(0).toString() == "broker_control" && !q.next());
            readRow();
            execute(db_, "PRAGMA journal_mode=WAL");
            execute(db_, "PRAGMA synchronous=FULL");
        }
        readRow();
    } catch (...) {
        db_.close();
        db_ = QSqlDatabase();
        QSqlDatabase::removeDatabase(connection_);
        throw;
    }
}
std::unique_ptr<ControlJournal> ControlJournal::createForProfile(const QString& path,
                                                                 PreparedRoot& proof) {
    const auto id = proof.deviceId();
    privatePath(path);
    QFile file(path);
    need(file.open(QIODevice::WriteOnly | QIODevice::NewOnly), "CONTROL_STORE_ALREADY_EXISTS");
    need(file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner),
         "CONTROL_PATH_REJECTED");
    file.close();
    // A failed/partial initial journal never recreates Root or resets floors.
    auto store = std::unique_ptr<ControlJournal>(new ControlJournal(path, id, true));
    need(proof.deviceId() == id, "CREDENTIAL_CANCELLED");
    return store;
}
std::unique_ptr<ControlJournal> ControlJournal::openExisting(const QString& path,
                                                             const QString& id) {
    return std::unique_ptr<ControlJournal>(new ControlJournal(path, id, false));
}
ControlJournal::~ControlJournal() {
    db_.close();
    db_ = QSqlDatabase();
    QSqlDatabase::removeDatabase(connection_);
}
ControlState ControlJournal::readRow() {
    QSqlQuery q(db_);
    need(q.exec("SELECT "
                "version,device_id,generation,policy_revision,phase,typeof(generation),typeof("
                "policy_revision) FROM broker_control WHERE singleton=1") &&
         q.next());
    need(q.value(0).toInt() == 1 && q.value(1).toString() == deviceId_, "CONTROL_BINDING_INVALID");
    need(q.value(5).toString() == "integer" && q.value(6).toString() == "integer");
    const auto g = q.value(2).toLongLong(), p = q.value(3).toLongLong();
    const auto phase = q.value(4).toString();
    need(g >= 0 && quint64(g) <= Maximum && p >= 0 && quint64(p) <= Maximum &&
         (phase == "LOCKED" || phase == "ACTIVE" || phase == "REVOKING"));
    need((phase == "LOCKED") || (g > 0 && p > 0));
    need((g == 0) == (p == 0)); // Only a fresh locked journal has zero counters.
    need(!q.next());
    QSqlQuery count(db_);
    need(count.exec("SELECT COUNT(*) FROM broker_control") && count.next() &&
         count.value(0).toInt() == 1);
    return {deviceId_, quint64(g), quint64(p), phase};
}
ControlState ControlJournal::read() { return readRow(); }
ControlState ControlJournal::transaction(const std::function<ControlState(ControlState)>& change) {
    execute(db_, "BEGIN IMMEDIATE");
    try {
        const auto before = readRow(), after = change(before);
        QSqlQuery q(db_);
        q.prepare("UPDATE broker_control SET generation=?,policy_revision=?,phase=? WHERE "
                  "singleton=1 AND generation=? AND policy_revision=? AND phase=?");
        q.addBindValue(qlonglong(after.generation));
        q.addBindValue(qlonglong(after.policyRevision));
        q.addBindValue(after.phase);
        q.addBindValue(qlonglong(before.generation));
        q.addBindValue(qlonglong(before.policyRevision));
        q.addBindValue(before.phase);
        need(q.exec() && q.numRowsAffected() == 1, "CONTROL_CONFLICT");
        execute(db_, "COMMIT");
        return after;
    } catch (...) {
        db_.rollback();
        throw;
    }
}
ControlState ControlJournal::reserveSession(PreparedRoot& proof) {
    const auto id = proof.deviceId();
    need(id == deviceId_, "CONTROL_BINDING_INVALID");
    return transaction([&](ControlState s) {
        need(s.phase == "LOCKED", "CONTROL_NOT_LOCKED");
        need(s.generation < Maximum && s.policyRevision < Maximum, "CONTROL_COUNTER_EXHAUSTED");
        need(proof.deviceId() == id, "CREDENTIAL_CANCELLED");
        ++s.generation;
        ++s.policyRevision;
        s.phase = "ACTIVE";
        return s;
    });
}
ControlState ControlJournal::reservePolicyRevision(quint64 expectedGeneration) {
    return transaction([&](ControlState s) {
        need(s.phase == "ACTIVE", "CONTROL_NOT_ACTIVE");
        need(s.generation == expectedGeneration, "CONTROL_CONFLICT");
        need(s.policyRevision < Maximum, "CONTROL_COUNTER_EXHAUSTED");
        ++s.policyRevision;
        return s;
    });
}
ControlState ControlJournal::beginFullLock() {
    return transaction([](ControlState s) {
        if (s.phase == "LOCKED" || s.phase == "REVOKING")
            return s;
        need(s.generation < Maximum && s.policyRevision < Maximum, "CONTROL_COUNTER_EXHAUSTED");
        ++s.generation;
        ++s.policyRevision;
        s.phase = "REVOKING";
        return s;
    });
}
ControlState ControlJournal::confirmStopped(const ControlState& pending) {
    return transaction([&](ControlState s) {
        need(pending.phase == "REVOKING" && pending.deviceId == s.deviceId &&
                 pending.generation == s.generation && pending.policyRevision == s.policyRevision,
             "CONTROL_CONFLICT");
        if (s.phase == "LOCKED")
            return s; // Repeated completion after reply loss.
        need(s.phase == "REVOKING", "CONTROL_NOT_REVOKING");
        s.phase = "LOCKED";
        return s;
    });
}
ControlState ControlJournal::mergeStoppedDaemonFloors(const ControlState& expected,
                                                      quint64 minGeneration, quint64 minPolicy) {
    need(minGeneration >= 1 && minGeneration <= Maximum && minPolicy >= 1 && minPolicy <= Maximum,
         "CONTROL_COUNTER_INVALID");
    return transaction([&](ControlState s) {
        need(expected.deviceId == s.deviceId && expected.generation == s.generation &&
                 expected.policyRevision == s.policyRevision && expected.phase == s.phase,
             "CONTROL_CONFLICT");
        s.generation = std::max(s.generation, minGeneration);
        s.policyRevision = std::max(s.policyRevision, minPolicy);
        s.phase = "LOCKED";
        return s;
    });
}
} // namespace dmash::broker

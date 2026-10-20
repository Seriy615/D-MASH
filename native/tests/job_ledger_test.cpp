#include "job_ledger.h"
#include <QCoreApplication>
#include <QFile>
#include <QProcess>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <QUuid>
#include <QVariant>
#include <cstdlib>
#include <stdexcept>
#include <thread>
using dmash::JobLedger;
namespace {
const QString node(64, 'a'), scope(64, 'b'), other(64, 'c');
const QByteArray key(32, 't'), body = "opaque-E2EE-fixture-not-plaintext-application-data";
constexpr qint64 now = 100000, day = 86400000;
void check(bool ok) {
    if (!ok)
        throw std::runtime_error("job test failed");
}
template <class F> void rejected(F f) {
    bool denied = false;
    try {
        f();
    } catch (const std::exception&) {
        denied = true;
    }
    check(denied);
}
qint64 n(const QJsonObject& j, const char* name) { return j.value(name).toInteger(); }
QString s(const QJsonObject& j, const char* name) { return j.value(name).toString(); }
int count(const QString& file) {
    const auto id = QUuid::createUuid().toString();
    int total = 0;
    {
        auto db = QSqlDatabase::addDatabase("QSQLITE", id);
        db.setDatabaseName(file);
        check(db.open());
        {
            QSqlQuery q(db);
            check(q.exec("SELECT count(*) FROM native_jobs") && q.next());
            total = q.value(0).toInt();
        }
        db.close();
    }
    QSqlDatabase::removeDatabase(id);
    return total;
}
QString firstId(const QString& file) {
    const auto id = QUuid::createUuid().toString();
    QString result;
    {
        auto db = QSqlDatabase::addDatabase("QSQLITE", id);
        db.setDatabaseName(file);
        check(db.open());
        {
            QSqlQuery q(db);
            check(q.exec("SELECT id FROM native_jobs ORDER BY id LIMIT 1"));
            if (q.next())
                result = q.value(0).toString();
        }
        db.close();
    }
    QSqlDatabase::removeDatabase(id);
    return result;
}
void crash(const QString& exe, const QString& file, const QString& destination,
           const QString& point) {
    QProcess child;
    child.start(exe, {"crash", file, destination, point});
    check(child.waitForFinished(15000) && child.exitCode() == 73);
}
} // namespace
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() == 5 && args[1] == "crash") {
        JobLedger ledger(args[2], node, key);
        ledger.acquire(1, 1, true, false);
        ledger.setTestHook([&](const char* point) {
            if (args[4] == QString::fromLatin1(point))
                std::_Exit(73);
        });
        ledger.accept(scope, args[3], "crash-op", body, now + day, now);
        return 2;
    }
    QTemporaryDir root;
    check(root.isValid());
    const auto file = root.filePath("jobs.sqlite");
    dmash::JobLimits limits;
    limits.globalJobs = 2;
    limits.ownerJobs = 2;
    limits.destinationJobs = 1;
    JobLedger first(file, node, key, limits);
    check(first.acquire(1, 1, true, false) == 1);
    const auto destination = first.installDestination(
        scope, "verified-node-v4-certificate-and-active-reply", 1, now + day, now);
    const auto accepted = first.accept(scope, destination, "op-1", body, now + day, now);
    const auto id = s(accepted, "id");
    check(s(first.accept(scope, destination, "op-1", body, now + day, now), "id") == id &&
          count(file) == 1);
    rejected([&] { first.accept(scope, destination, "op-1", body + "changed", now + day, now); });
    check(!first.job(other, id) && !first.destination(other, destination));
    rejected([&] { first.accept(other, destination, "op", body, now + day, now); });
    rejected([&] { first.accept(scope, destination, "op-2", body, now + day, now); });
    auto claimed = first.claim(id, n(accepted, "revision"), now);
    check(claimed.has_value());
    const auto attempt = s(*claimed, "attemptToken");
    check(first.maySend(id, attempt, now));
    first.setPolicy(2, false, false);
    check(!first.maySend(id, attempt, now) && first.due(now).isEmpty());
    first.setPolicy(3, true, false);
    check(first.maySend(id, attempt, now));
    check(first.cancel(scope, id, now) && !first.maySend(id, attempt, now));
    check(!first.finish(id, attempt, "TRANSPORT_SENT", 0, now));
    const auto destination2 =
        first.installDestination(scope, "another-verified-certificate", 1, now + day, now);
    auto second = first.accept(scope, destination2, "op-2", body, now + day, now);
    const auto id2 = s(second, "id");
    rejected([&] { first.accept(other, destination2, "op-3", body, now + day, now); });
    dmash::JobLimits lower;
    lower.globalJobs = lower.ownerJobs = lower.destinationJobs = 1;
    JobLedger owner2(file, node, key, lower);
    check(owner2.acquire(1, 3, true, false) == 2);
    rejected([&] { first.policy(); });
    rejected([&] { first.maySend(id, attempt, now); });
    check(owner2.job(scope, id).has_value() && count(file) == 2);
    check(s(owner2.accept(scope, destination2, "op-2", body, now + day, now), "id") == id2);
    auto due = owner2.due(now);
    check(due.size() == 1 && s(due[0], "id") == id2);
    auto retry = owner2.claim(id2, n(due[0], "revision"), now);
    check(retry.has_value());
    check(owner2.finish(id2, s(*retry, "attemptToken"), "TRANSPORT_SENT", 0, now));
    check(s(*owner2.job(scope, id2), "state") == "TRANSPORT_SENT" &&
          owner2.nextDeadline() == now + 2 * day + 1);
    rejected([&] { JobLedger wrong(file, node, QByteArray(32, 'w')); });
    rejected([&] { JobLedger wrongNode(file, QString(64, 'd'), key); });
    check(owner2.current());
    bool threadDenied = false;
    std::thread wrongThread([&] {
        try {
            owner2.current();
        } catch (const std::exception&) {
            threadDenied = true;
        }
    });
    wrongThread.join();
    check(threadDenied);
    for (const auto& suffix : {QString(), QString("-wal")}) {
        QFile raw(file + suffix);
        if (raw.open(QIODevice::ReadOnly))
            check(!raw.readAll().contains(body));
    }
    check(owner2.prune(now + 2 * day + 1) == 2 && count(file) == 0);
    check(n(owner2.revoke(1, 4), "transportGeneration") == 2);
    {
        JobLedger staleGrant(file, node, key);
        rejected([&] { staleGrant.acquire(1, 5, true, false); });
    }
    {
        JobLedger authorizedResume(file, node, key);
        check(authorizedResume.acquire(2, 5, true, false) == 3);
    }
    {
        const auto fairFile = root.filePath("fair.sqlite");
        JobLedger fair(fairFile, node, key);
        fair.acquire(1, 1, true, false);
        const auto a = fair.installDestination(scope, "route-a", 1, now + day, now),
                   b = fair.installDestination(other, "route-b", 1, now + day, now);
        auto ja = fair.accept(scope, a, "a", body, now + day, now),
             jb = fair.accept(other, b, "b", body, now + 1000, now);
        auto selected = fair.due(now, 2);
        check(selected.size() == 2 && s(selected[0], "scope") != s(selected[1], "scope"));
        check(fair.defer(s(ja, "id"), n(ja, "revision"), "WAITING_BOOTSTRAP", now + 30000, now));
        check(n(*fair.job(scope, s(ja, "id")), "attempts") == 0);
        fair.setPolicy(2, false, false);
        check(fair.due(now).isEmpty());
        check(fair.nextDeadline() == now + 1000);
        auto expired = fair.due(now + 1001);
        check(expired.size() == 1 && s(expired[0], "id") == s(jb, "id"));
        check(!fair.claim(s(jb, "id"), n(expired[0], "revision"), now + 1001));
        check(s(*fair.job(other, s(jb, "id")), "state") == "EXPIRED");
        check(s(fair.accept(other, b, "b", body, now + 1000, now + 1001), "id") == s(jb, "id"));
    }

    {
        JobLedger offline(root.filePath("offline.sqlite"), node, key);
        offline.acquire(1, 1, true, false);
        const auto dest = offline.installDestination(scope, "route", 1, now + day, now);
        const auto j = offline.accept(scope, dest, "intent", body, now + day, now);
        check(offline.defer(s(j, "id"), n(j, "revision"), "WAITING_BOOTSTRAP", now + day, now));
        check(offline.due(now).isEmpty() && offline.nextDeadline() == now + day);
        const auto ready = offline.due(now, 2, true);
        check(ready.size() == 1);
        const auto claimed = offline.claim(s(j, "id"), n(ready[0], "revision"), now, true);
        check(claimed.has_value());
        check(offline.finish(s(j, "id"), s(*claimed, "attemptToken"), "TRANSPORT_SENT", 0, now));
        check(offline.nextDeadline() == now + 2 * day + 1);
        check(offline.prune(now + 2 * day + 1) == 1 && offline.nextDeadline() == std::nullopt);
    }

    for (const auto& point : {QString("accept-before-commit"), QString("accept-after-commit")}) {
        const auto path = root.filePath(point + ".sqlite");
        QString dest;
        {
            JobLedger initial(path, node, key);
            initial.acquire(1, 1, true, false);
            dest = initial.installDestination(scope, "public-route", 1, now + day, now);
        }
        crash(app.applicationFilePath(), path, dest, point);
        check(count(path) == (point == "accept-before-commit" ? 0 : 1));
        const auto committedId = firstId(path);
        JobLedger recovered(path, node, key);
        recovered.acquire(1, 1, true, false);
        const auto recoveredJob = recovered.accept(scope, dest, "crash-op", body, now + day, now);
        check(committedId.isEmpty() || s(recoveredJob, "id") == committedId);
        check(count(path) == 1 && s(recovered.accept(scope, dest, "crash-op", body, now + day, now),
                                    "id") == s(recoveredJob, "id"));
    }
}

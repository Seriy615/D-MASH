#include "control_journal.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QProcess>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <cstdlib>
#include <iostream>
using namespace dmash::broker;
static void check(bool ok) {
    if (!ok)
        throw std::runtime_error("control assertion failed");
}
template <class F> static void rejects(F f, const char* code) {
    bool fail = false;
    try {
        f();
    } catch (const Error& e) {
        fail = true;
        check(std::string(e.what()) == code);
    }
    check(fail);
}
static PreparedRoot prepared(RootCodec::Current current = [] { return true; }) {
    QFile f(BROKER_FIXTURE);
    check(f.open(QIODevice::ReadOnly));
    auto root = QJsonDocument::fromJson(f.readAll()).object();
    return RootCodec::openExisting(root.value("records").toObject().value("modern_id").toObject(),
                                   root.value("pin").toString().toUtf8(), std::move(current));
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        auto proof = prepared();
        if (argc == 3 && QString::fromLocal8Bit(argv[1]) == "reserve") {
            try {
                auto j =
                    ControlJournal::openExisting(QString::fromLocal8Bit(argv[2]), proof.deviceId());
                j->reserveSession(proof);
                return 0;
            } catch (const Error& e) {
                if (std::string(e.what()) == "CONTROL_NOT_LOCKED")
                    return 10;
                throw;
            }
        }
        if (argc == 3 && QString::fromLocal8Bit(argv[1]) == "crash-lock") {
            auto journal =
                ControlJournal::openExisting(QString::fromLocal8Bit(argv[2]), proof.deviceId());
            journal->beginFullLock();
            std::_Exit(23); // No SQL destructors/checkpoint after committed lock intent.
        }
        QTemporaryDir dir;
        check(dir.isValid());
        const auto path = dir.filePath("broker-control.sqlite");
        rejects([&] { ControlJournal::openExisting(path, proof.deviceId()); },
                "CONTROL_STORE_MISSING");
        check(!QFile::exists(path));
        auto first = ControlJournal::createForProfile(path, proof);
        auto second = ControlJournal::openExisting(path, proof.deviceId());
        check(first->read().phase == "LOCKED" && first->read().generation == 0);
        rejects([&] { ControlJournal::createForProfile(path, proof); },
                "CONTROL_STORE_ALREADY_EXISTS");
        rejects([&] { ControlJournal::openExisting(path, "d1_" + QString(43, 'a')); },
                "CONTROL_BINDING_INVALID");
        int budget = 100;
        auto canceled = prepared([&] { return --budget >= 0; });
        budget = 1;
        rejects([&] { first->reserveSession(canceled); }, "CREDENTIAL_CANCELLED");
        check(first->read().generation == 0 && first->read().phase == "LOCKED");
        const auto a = first->reserveSession(proof);
        check(a.phase == "ACTIVE" && a.generation == 1 && a.policyRevision == 1);
        rejects([&] { second->reserveSession(proof); }, "CONTROL_NOT_LOCKED");
        rejects([&] { second->reservePolicyRevision(2); }, "CONTROL_CONFLICT");
        check(first->reservePolicyRevision(1).policyRevision == 2);
        first.reset();
        second.reset();
        QProcess crashed;
        crashed.start(app.applicationFilePath(), {"crash-lock", path});
        check(crashed.waitForStarted() && crashed.waitForFinished(30000) &&
              crashed.exitCode() == 23);
        auto recovered = ControlJournal::openExisting(path, proof.deviceId());
        const auto pending = recovered->read();
        check(pending.phase == "REVOKING" && pending.generation == 2 &&
              pending.policyRevision == 3);
        check(recovered->beginFullLock().generation == 2);
        check(recovered->read().phase == "REVOKING");
        rejects([&] { recovered->reserveSession(proof); }, "CONTROL_NOT_LOCKED");
        auto stale = pending;
        stale.generation = 1;
        rejects([&] { recovered->confirmStopped(stale); }, "CONTROL_CONFLICT");
        check(recovered->confirmStopped(pending).phase == "LOCKED");
        check(recovered->confirmStopped(pending).phase == "LOCKED");
        auto next = recovered->reserveSession(proof);
        check(next.generation == 3 && next.policyRevision == 4);
        const auto p2 = recovered->beginFullLock();
        check(p2.generation == 4);
        recovered->confirmStopped(p2);
        recovered.reset();
        // Independent processes/SQLite connections compete for one reserved session.
        QProcess one, two;
        one.start(app.applicationFilePath(), {"reserve", path});
        two.start(app.applicationFilePath(), {"reserve", path});
        check(one.waitForStarted() && two.waitForStarted());
        check(one.waitForFinished(30000) && two.waitForFinished(30000));
        check((one.exitCode() == 0 && two.exitCode() == 10) ||
              (one.exitCode() == 10 && two.exitCode() == 0));
        auto final = ControlJournal::openExisting(path, proof.deviceId());
        check(final->read().generation == 5 && final->read().phase == "ACTIVE");
        const auto activeBeforeCrash = final->read();
        auto wrongState = activeBeforeCrash;
        wrongState.generation = 4;
        rejects([&] { final->mergeStoppedDaemonFloors(wrongState, 8, 9); }, "CONTROL_CONFLICT");
        rejects([&] { final->mergeStoppedDaemonFloors(activeBeforeCrash, 9007199254740992ULL, 9); },
                "CONTROL_COUNTER_INVALID");
        auto merged = final->mergeStoppedDaemonFloors(activeBeforeCrash, 8, 9);
        check(merged.phase == "LOCKED" && merged.generation == 8 && merged.policyRevision == 9);
        auto afterCrash = final->reserveSession(proof);
        check(afterCrash.generation == 9 && afterCrash.policyRevision == 10);
        auto p3 = final->beginFullLock();
        final->confirmStopped(p3);
        final.reset();
        // No secret/plain PIN is persisted in the public control metadata DB.
        QFile bytes(path);
        check(bytes.open(QIODevice::ReadOnly));
        const auto data = bytes.readAll();
        check(!data.contains("synthetic-only-master") && !data.contains(QByteArray(32, char(7))));
        bytes.close();
        {
            auto db = QSqlDatabase::addDatabase("QSQLITE", "control-corruption-fixture");
            db.setDatabaseName(path);
            check(db.open());
            {
                QSqlQuery q(db);
                check(q.exec("UPDATE broker_control SET generation=0"));
            }
            db.close();
        }
        QSqlDatabase::removeDatabase("control-corruption-fixture");
        rejects([&] { ControlJournal::openExisting(path, proof.deviceId()); },
                "CONTROL_STORE_CORRUPT");
        const auto corrupt = dir.filePath("corrupt.sqlite");
        QFile bad(corrupt);
        check(bad.open(QIODevice::WriteOnly));
        bad.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        bad.write("not sqlite");
        bad.close();
        rejects([&] { ControlJournal::openExisting(corrupt, proof.deviceId()); },
                "CONTROL_STORE_CORRUPT");
        check(bad.open(QIODevice::ReadOnly) && bad.readAll() == "not sqlite");
        std::cout
            << "PASS broker control WAL/FULL reservation, revoke floor, crash pending reopen, "
               "exact ACK/idempotence, independent process race, missing/corrupt refusal\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << "\n";
        return 1;
    }
}

#include "broker_service.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QProcess>
#include <QSaveFile>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <iostream>
#include <thread>
using namespace dmash::broker;
static void check(bool ok) {
    if (!ok)
        throw std::runtime_error("credential assertion failed");
}
template <class F> void rejects(F f, const char *code) {
    bool threw = false;
    try {
        f();
    } catch (const Error &e) {
        threw = true;
        check(std::string(e.what()) == code);
    }
    check(threw);
}
static QByteArray key(32, 's');
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    try {
        QFile fixture(BROKER_FIXTURE);
        check(fixture.open(QIODevice::ReadOnly));
        auto f = QJsonDocument::fromJson(fixture.readAll()).object();
        auto root = f.value("records").toObject().value("modern_id").toObject();
        auto pin = f.value("pin").toString().toUtf8();
        auto current = [] { return true; };
        if (argc == 3 && QString(argv[1]) == "--crash-after-cas") {
            auto store = CredentialStore::openExisting(QString::fromLocal8Bit(argv[2]), key);
            auto before = store->read();
            auto proof = RootCodec::openExisting(before.root, pin, current);
            store->commit(before, before.root, proof, false, current);
            std::_Exit(0);
        }
        QTemporaryDir dir(QDir::homePath() +
                          "/.cache/dmash-native-20261020/broker-synthetic-XXXXXX");
        check(dir.isValid());
        QFile::setPermissions(dir.path(), QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                              QFileDevice::ExeOwner);
        auto path = dir.filePath("credentials.db"),
             backup = dir.filePath("before-import.encrypted"), control = dir.filePath("control.db");
        rejects([&] { CredentialStore::openExisting(path, key); }, "ROOT_MISSING");
        check(!QFile::exists(path));
        QJsonObject rootStore{{"name", "roots"}, {"records", QJsonArray{root}}};
        QJsonObject historyStore{
            {"name", "messages"},
            {"records",
             QJsonArray{QJsonObject{{"id", "saved-row"}, {"ciphertext", "preserve-every-byte"}}}}};
        QJsonArray databases{
            QJsonObject{{"name", "root-db"}, {"stores", QJsonArray{rootStore}}},
            QJsonObject{{"name", "account-history"}, {"stores", QJsonArray{historyStore}}}};
        QJsonObject package{
            {"version", 1},
            {"inventoryComplete", true},
            {"root", root},
            {"ancillary",
             QJsonObject{{"localStorage", QJsonObject{{"opaque-setting", "retained"}}}}},
            {"databases", databases}};
        auto proof = RootCodec::openExisting(root, pin, current);
        auto incomplete = package;
        incomplete["inventoryComplete"] = false;
        rejects(
            [&] { CredentialStore::importProfile(path, key, incomplete, proof, backup, current); },
            "COMPLETE_PROFILE_REQUIRED");
        check(!QFile::exists(path));
        auto store = CredentialStore::importProfile(path, key, package, proof, backup, current);
        auto original = store->read();
        check(original.deviceId == f.value("deviceId") &&
              store->exportOriginalProfile() == package && QFile::exists(backup));
        QFile backupFile(backup);
        check(backupFile.open(QIODevice::ReadOnly));
        auto backupBytes = backupFile.readAll();
        check(!backupBytes.contains("saved-row") && !backupBytes.contains("wrappedRoot"));
        check(CredentialStore::readProfileBackup(backup, key) == package);
        auto restored = CredentialStore::importProfile(
            dir.filePath("restored.db"), key, CredentialStore::readProfileBackup(backup, key),
            proof, dir.filePath("restored.backup"), current);
        check(restored->exportOriginalProfile() == package &&
              restored->read().deviceId == original.deviceId);
        restored.reset();
        rejects([&] { CredentialStore::openExisting(path, QByteArray(32, 'x')); },
                "CREDENTIAL_AUTH_FAILED");
        auto second = CredentialStore::openExisting(path, key);
        auto committed = store->commit(original, root, proof, false, current);
        check(committed.revision == original.revision + 1);
        rejects([&] { second->commit(original, root, proof, false, current); },
                "CREDENTIAL_CONFLICT");
        int checks = 0;
        rejects(
            [&] {
                store->commit(committed, committed.root, proof, false,
                              [&] { return ++checks < 2; });
            },
            "CREDENTIAL_CANCELLED");
        check(store->read().revision == committed.revision);
        auto altered = committed.root;
        altered["materials"] = QJsonObject{};
        auto wrong = RootCodec::openExisting(altered, pin, current);
        rejects([&] { store->commit(committed, altered, wrong, false, current); },
                "CREDENTIAL_MATERIAL_CHANGED");
        second.reset();
        store.reset();
        QProcess child;
        child.start(QCoreApplication::applicationFilePath(), {"--crash-after-cas", path});
        check(child.waitForFinished(30000) && child.exitCode() == 0);
        store = CredentialStore::openExisting(path, key);
        check(store->read().revision == committed.revision + 1 &&
              store->exportOriginalProfile() == package);
        store.reset();
        // Competing connections race the SAME revision, never create a replacement Root.
        auto baseline = CredentialStore::openExisting(path, key)->read();
        std::atomic<int> ready{0};
        auto race = [&] {
            auto s = CredentialStore::openExisting(path, key);
            auto p = RootCodec::openExisting(baseline.root, pin, current);
            ++ready;
            while (ready < 2)
                std::this_thread::yield();
            try {
                s->commit(baseline, baseline.root, p, false, current);
                return true;
            } catch (const Error &e) {
                check(std::string(e.what()) == "CREDENTIAL_CONFLICT");
                return false;
            }
        };
        auto a = std::async(std::launch::async, race), b = std::async(std::launch::async, race);
        check(a.get() != b.get());
        BrokerService service(path, key, control);
        check(service.unlock("wrong").get().code == "UNLOCK_FAILED");
        check(service.unlock(pin).get().ok);
        auto opening = service.unlock(pin);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        service.cancel();
        check(opening.get().code == "CREDENTIAL_CANCELLED");
        check(service.unlock(pin).get().ok);
        auto exported = service.transport({}, false).get();
        check(exported.ok && exported.transportBundle.size() == 7 &&
              exported.control.phase == "ACTIVE");
        check(service.isCurrentTransportResult(exported));
        const auto paused = service.pauseTransport().get();
        check(paused.ok && paused.control.phase == "REVOKING" &&
              paused.control.generation > exported.control.generation);
        check(!service.isCurrentTransportResult(exported));
        check(service.confirmTransportStopped(paused.control).get().control.phase == "LOCKED");
        // Resume the same prepared Root, without PIN re-entry or material changes.
        const auto resumed = service.transport({}, false).get();
        check(resumed.ok && service.isCurrentTransportResult(resumed));
        check(resumed.control.generation > paused.control.generation);
        for (const auto& name : {"nodeSeed", "baseNcrh", "storageKey"})
            check(resumed.transportBundle.value(name) == exported.transportBundle.value(name));
        check(!service.isCurrentTransportResult(exported));
        auto locking = service.fullRootLock().get();
        check(!service.isCurrentTransportResult(exported));
        check(!service.isCurrentTransportResult(resumed));
        check(locking.ok && locking.control.phase == "REVOKING" &&
              locking.control.generation > exported.control.generation);
        check(service.transport({}, false).get().code == "CREDENTIAL_CANCELLED");
        check(service.confirmTransportStopped(locking.control).get().control.phase == "LOCKED");
        // Cancel AFTER durable commit reports committed=true and keeps new credentials.
        auto changed = service
                           .change(pin, "synthetic-next-master", "synthetic-wipe",
                                   [&] {
                                       service.cancel();
                                       return false;
                                   })
                           .get();
        check(!changed.ok && changed.committed && changed.cleanupPending);
        check(service.unlock(pin).get().code == "UNLOCK_FAILED");
        check(service.unlock("synthetic-next-master").get().ok);
        check(service.transport({}, false).get().code == "CREDENTIAL_MIGRATION_REQUIRED");
        auto clean = service.resumeCleanup("synthetic-next-master", [] { return true; }).get();
        check(clean.ok && clean.committed && !clean.cleanupPending);
        auto final = CredentialStore::openExisting(path, key);
        check(final->exportOriginalProfile() == package &&
              final->read().root.value("materials") == root.value("materials"));
        auto newProof =
            RootCodec::openExisting(final->read().root, "synthetic-next-master", current);
        if (argc == 2) {
            QSaveFile exported(QString::fromLocal8Bit(argv[1]));
            check(exported.open(QIODevice::WriteOnly));
            const auto bytes = QJsonDocument(final->read().root).toJson();
            check(exported.write(bytes) == bytes.size() && exported.commit());
        }
        check(newProof.deviceId() == f.value("deviceId"));
        // Legacy Root migration follows exactly the same import/CAS path.
        auto legacy = f.value("records").toObject().value("legacy_d").toObject();
        package["root"] = legacy;
        auto legacyProof = RootCodec::openExisting(legacy, pin, current);
        auto legacyStore =
            CredentialStore::importProfile(dir.filePath("legacy.db"), key, package, legacyProof,
                                           dir.filePath("legacy.backup"), current);
        legacyStore.reset();
        BrokerService legacyService(dir.filePath("legacy.db"), key, dir.filePath("legacy.control"));
        auto migration =
            legacyService.change(pin, "legacy-next", "legacy-wipe", [] { return true; }).get();
        check(migration.ok && migration.committed && migration.deviceId == f.value("deviceId"));
        std::cout << "PASS encrypted complete import/backup preserved history; missing/wrong-key "
                     "refusal; CAS/concurrent/crash reopen; worker cancel; committed cleanup "
                     "recovery; legacy migration; lock generation\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "FAIL " << e.what() << "\n";
        return 1;
    }
}

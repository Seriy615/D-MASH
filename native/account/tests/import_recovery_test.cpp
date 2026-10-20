#include "account_service.h"
#include "account_sql_store.h"
#include "broker_service.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QProcess>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <iostream>
using namespace dmash::account;
static void check(bool b, const char *c) {
    if (!b)
        throw std::runtime_error(c);
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    try {
        QFile f(ACCOUNT_FIXTURE);
        check(f.open(QIODevice::ReadOnly), "fixture");
        auto fixture = QJsonDocument::fromJson(f.readAll()).object(),
             profile = fixture.value("profile").toObject();
        if (argc == 4 && QString(argv[1]) == "--crash-import") {
            const auto boundary = QString::fromLocal8Bit(argv[3]);
            AccountSqlStore::importProfile(QString::fromLocal8Bit(argv[2]), profile,
                                           [&](const QString &where) {
                                               if (where == boundary)
                                                   std::_Exit(0);
                                           });
            return 2;
        }
        if (argc == 3 && QString(argv[1]) == "--import-once") {
            AccountSqlStore::importProfile(QString::fromLocal8Bit(argv[2]), profile);
            return 0;
        }
        QTemporaryDir dir(QDir::homePath() +
                          "/.cache/dmash-native-20261020/account-recovery-synthetic-XXXXXX");
        check(dir.isValid(), "private dir");
        QFile::setPermissions(dir.path(), QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                              QFileDevice::ExeOwner);
        const auto pin = fixture.value("rootPin").toString().toUtf8(),
                   password = fixture.value("password").toString().toUtf8();
        const auto identity = fixture.value("identity").toString();
        int index = 0;
        for (const auto &boundary :
             {"before-stage-commit", "after-stage-commit", "after-publish"}) {
            const auto caseDir = dir.filePath(QString("case-%1").arg(++index));
            check(QDir().mkpath(caseDir), "case directory");
            check(QFile::setPermissions(caseDir, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                                     QFileDevice::ExeOwner), "private case");
            const auto accountPath = caseDir + "/account.db";
            const auto brokerPath = caseDir + "/credentials.db", control = caseDir + "/control.db";
            {
                dmash::broker::BrokerService first(brokerPath, QByteArray(32, 'r'), control);
                auto committed = first.importProfile(profile, pin, caseDir + "/source.backup").get();
                check(committed.ok && committed.committed && committed.accountImportPhase == "PENDING",
                      "broker durable pending before Account import");
            }
            QProcess crashed;
            crashed.start(QCoreApplication::applicationFilePath(),
                          {"--crash-import", accountPath, boundary});
            check(crashed.waitForFinished(30000) && crashed.exitCode() == 0,
                  "real child abrupt exit");
            check(QFile::exists(accountPath) == (QString(boundary) == "after-publish"),
                  "only fully committed database published");
            // Restart with only the durable broker database/key; no original input/source is
            // reread.
            dmash::broker::BrokerService broker(brokerPath, QByteArray(32, 'r'), control);
            check(broker.accountImportInventory().get().code == "ROOT_UNLOCK_REQUIRED",
                  "locked inventory refusal");
            check(broker.unlock(pin).get().ok, "Root restart unlock");
            auto inventory = broker.accountImportInventory().get();
            check(inventory.ok && inventory.profileInventory == profile,
                  "authenticated retained inventory");
            AccountService::RegistryReader reader = [&](const QJsonArray &rows) {
                auto result = broker.readAccountRegistry(rows).get();
                if (!result.ok)
                    throw AccountError(result.code.toUtf8().constData());
                return result.accountRegistry;
            };
            {
                AccountService service(accountPath, {}, reader);
                auto published = service.importProfile(inventory.profileInventory).get();
                check(published.ok && published.importProof.has_value(), "resume published receipt");
                auto acknowledged = broker.confirmAccountImport(*published.importProof).get();
                check(acknowledged.ok && acknowledged.accountImportPhase == "COMMITTED" &&
                          acknowledged.accountDatabasePath == accountPath,
                      "durable published acknowledgement");
                check(broker.accountImportInventory().get().code == "ACCOUNT_IMPORT_ALREADY_COMMITTED",
                      "accepted profile cannot replay browser snapshot");
                auto login = service.login(identity, password).get();
                check(login.ok &&
                          login.value.value("accountPublicId") == fixture.value("accountPublicId"),
                      "same Account after resume");
                check(service.listHistory("local:saved-messages:v1").get().rows.size() == 1,
                      "original Saved after resume");
                auto local =
                    service
                        .sendText("local:saved-messages:v1", QString(64, char('c' + index)),
                                  "recovery retained native row")
                        .get();
                check(local.ok && local.value.value("accepted") == true, "native row accepted");
                check(service.importProfile(inventory.profileInventory).get().ok,
                      "same live import retry");
                check(service.listHistory("local:saved-messages:v1").get().rows.size() == 2,
                      "retry preserves accepted native row");
                auto different = inventory.profileInventory;
                different["ancillary"] = QJsonObject{{"different", true}};
                auto rejected = service.importProfile(different).get();
                check(!rejected.ok && rejected.code == "ACCOUNT_PROFILE_CONFLICT",
                      "different inventory cannot overwrite");
            }
            {
                AccountService restarted(accountPath, {}, reader);
                check(restarted.importProfile(inventory.profileInventory).get().ok,
                      "accepted publish/reply loss idempotent");
                check(restarted.login(identity, password).get().ok, "relogin accepted existing DB");
                check(restarted.listHistory("local:saved-messages:v1").get().rows.size() == 2,
                      "restart import preserves all accepted history");
            }
            const auto preserved = accountPath + ".preserved";
            check(QFile::rename(accountPath, preserved), "preserve accepted database");
            {
                AccountService missing(accountPath, {}, reader);
                check(!missing.verifyPublishedImport().get().ok, "missing accepted DB refuses");
                check(broker.accountImportInventory().get().code == "ACCOUNT_IMPORT_ALREADY_COMMITTED",
                      "missing accepted DB cannot replay old inventory");
            }
            check(QFile::rename(preserved, accountPath), "restore preserved accepted database");
            {
                AccountService restored(accountPath, {}, reader);
                auto verified = restored.verifyPublishedImport().get();
                check(verified.ok && verified.importProof.has_value(), "verify accepted DB");
                check(broker.confirmAccountImport(*verified.importProof).get().ok, "idempotent ack");
                check(restored.login(identity, password).get().ok &&
                          restored.listHistory("local:saved-messages:v1").get().rows.size() == 2,
                      "explicit original restoration retains native writes");
            }
        }
        // Prior native schema has no publication receipt: never infer initial-import permission.
        const auto oldPath = dir.filePath("old-credentials.db");
        const auto oldControl = dir.filePath("old-control.db");
        {
            dmash::broker::BrokerService old(oldPath, QByteArray(32, 'o'), oldControl);
            check(old.importProfile(profile, pin, dir.filePath("old.backup")).get().ok, "old seed");
        }
        {
            auto db = QSqlDatabase::addDatabase("QSQLITE", "old-schema-test");
            db.setDatabaseName(oldPath);
            check(db.open(), "old schema open");
            {
                QSqlQuery query(db);
                check(query.exec("ALTER TABLE credentials DROP COLUMN account_import_phase") &&
                          query.exec("ALTER TABLE credentials DROP COLUMN account_database_path"),
                      "prepare old schema");
            }
            db.close();
        }
        QSqlDatabase::removeDatabase("old-schema-test");
        {
            dmash::broker::BrokerService migrated(oldPath, QByteArray(32, 'o'), oldControl);
            auto opened = migrated.unlock(pin).get();
            check(opened.ok && opened.accountImportPhase == "UNVERIFIED", "old migration unverified");
            check(migrated.accountImportInventory().get().code == "ACCOUNT_IMPORT_RECOVERY_UNVERIFIED",
                  "old schema cannot silently replay");
            auto existing = AccountSqlStore::openExisting(dir.filePath("case-1/account.db"));
            check(migrated.confirmAccountImport(existing->publishedImportProof()).get().ok,
                  "old schema accepts verified existing database");
            auto otherProfile = profile;
            otherProfile["ancillary"] = QJsonObject{{"other", true}};
            auto other = AccountSqlStore::importProfile(dir.filePath("other.db"), otherProfile);
            check(migrated.confirmAccountImport(other->publishedImportProof()).get().code ==
                      "ACCOUNT_IMPORT_DIGEST_MISMATCH", "receipt digest must match canonical inventory");
        }
        // Normal validation failure leaves no final file and retries without resetting
        // source/identity.
        auto broken = profile;
        QJsonArray databases;
        for (auto value : profile.value("databases").toArray())
            if (value.toObject().value("name") != "dm_gamma_vault")
                databases.append(value);
        broken["databases"] = databases;
        auto path = dir.filePath("validation.db");
        bool failed = false;
        try {
            AccountSqlStore::importProfile(path, broken);
        } catch (const AccountError &) {
            failed = true;
        }
        check(failed && !QFile::exists(path), "failed validation never publishes partial final");
        check(bool(AccountSqlStore::importProfile(path, profile)),
              "retry malformed then correct profile");
        // Independent publishers may race; same inventory converges without overwriting an accepted
        // DB.
        auto concurrent = dir.filePath("concurrent.db");
        QProcess a, b;
        a.start(QCoreApplication::applicationFilePath(), {"--import-once", concurrent});
        b.start(QCoreApplication::applicationFilePath(), {"--import-once", concurrent});
        check(a.waitForFinished(30000) && b.waitForFinished(30000) && a.exitCode() == 0 &&
                  b.exitCode() == 0,
              "concurrent no-overwrite publishers");
        check(bool(AccountSqlStore::openExisting(concurrent)), "published database readable");
        std::cout << "PASS broker-commit/Account crash before+after stage commit/after "
                     "publication; same-profile inventory resume; idempotent retry preserves "
                     "native history; validation/concurrent publication\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "FAIL " << e.what() << "\n";
        return 1;
    }
}

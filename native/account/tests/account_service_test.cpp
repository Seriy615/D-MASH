#include "account_service.h"
#include "broker_service.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <atomic>
#include <iostream>
#include <thread>
using namespace dmash::account;
void check(bool b, const char *why) {
    if (!b)
        throw std::runtime_error(why);
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    try {
        QFile file(ACCOUNT_FIXTURE);
        check(file.open(QIODevice::ReadOnly), "fixture");
        auto f = QJsonDocument::fromJson(file.readAll()).object();
        auto profile = f.value("profile").toObject();
        auto identity = f.value("identity").toString();
        auto password = f.value("password").toString().toUtf8();
        QTemporaryDir dir(QDir::homePath() +
                          "/.cache/dmash-native-20261020/account-owner-synthetic-XXXXXX");
        check(dir.isValid(), "dir");
        QFile::setPermissions(dir.path(), QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                              QFileDevice::ExeOwner);
        auto path = dir.filePath("account.db");
        const auto rootPin = f.value("rootPin").toString().toUtf8();
        const auto brokerPath = dir.filePath("credentials.db");
        auto rootProof = dmash::broker::RootCodec::openExisting(profile.value("root").toObject(),
                                                                rootPin, [] { return true; });
        auto credentials = dmash::broker::CredentialStore::importProfile(
            brokerPath, QByteArray(32, 's'), profile, rootProof, dir.filePath("source.backup"),
            [] { return true; });
        credentials.reset();
        dmash::broker::BrokerService broker(brokerPath, QByteArray(32, 's'),
                                            dir.filePath("control.db"));
        check(broker.unlock(rootPin).get().ok, "Root unlock");
        AccountService::RegistryReader registry = [&](const QJsonArray &rows) {
            auto r = broker.readAccountRegistry(rows).get();
            if (!r.ok)
                throw AccountError(r.code.toUtf8().constData());
            return r.accountRegistry;
        };
        std::atomic<int> network{0};
        {
            AccountService service(
                path, [&](const QString &, const QString &, const QJsonObject &) -> QJsonObject {
                    ++network;
                    throw AccountError("TEST_NO_DAEMON");
                }, registry);
            auto imported = service.importProfile(profile).get();
            check(imported.ok && imported.importProof.has_value(), "import receipt");
            check(broker.confirmAccountImport(*imported.importProof).get().ok,
                  "broker publication acknowledgement");
            auto accounts = service.listAccounts().get();
            if (!accounts.ok)
                std::cerr << "listAccounts code " << accounts.code.toStdString() << "\n";
            check(accounts.ok && accounts.rows.size() == 1, "accounts");
            auto bad = service.login(identity, "wrong-password").get();
            if (bad.code != "ACCOUNT_PASSWORD_REJECTED")
                std::cerr << "bad code " << bad.code.toStdString() << "\n";
            check(!bad.ok && bad.code == "ACCOUNT_PASSWORD_REJECTED", "wrong password");
            auto login = service.login(identity, password).get();
            if (!login.ok)
                std::cerr << "login code " << login.code.toStdString() << "\n";
            check(login.ok && login.value.value("accountPublicId") == f.value("accountPublicId"),
                  "same signing identity");
            auto contacts = service.listContacts().get();
            if (!contacts.ok)
                std::cerr << contacts.code.toStdString() << "\n";
            check(contacts.ok && contacts.rows.size() == 2, "contacts preserved");
            const auto saved = QStringLiteral("local:saved-messages:v1");
            auto retained = service.listHistory(saved).get();
            if (!retained.ok)
                std::cerr << "history code " << retained.code.toStdString() << "\n";
            check(retained.ok && retained.rows.size() == 1 &&
                      retained.rows[0].toObject().value("text") == "retained Saved text",
                  "history preserved");
            auto sent = service.sendText(saved, QString(64, 'c'), "native Saved text").get();
            if (!sent.ok)
                std::cerr << "send code " << sent.code.toStdString() << "\n";
            check(sent.ok && sent.value.value("accepted") == true &&
                      sent.value.value("transportState") == "LOCAL",
                  "saved persisted");
            check(network == 0, "Saved has no daemon dependency");
            auto duplicate = service.sendText(saved, QString(64, 'c'), "native Saved text").get();
            check(duplicate.ok && duplicate.value.value("duplicate") == true,
                  "idempotent Saved retry");
            auto changed = service.sendText(saved, QString(64, 'c'), "different bytes").get();
            check(!changed.ok && changed.code == "ACCOUNT_OPERATION_CONFLICT",
                  "operation conflict");
            auto blocked =
                service.sendText(QString(64, 'a'), QString(64, 'd'), "remote text").get();
            check(!blocked.ok, "missing route never success");
            check(service.listHistory(saved).get().rows.size() == 2, "two exact rows");
            check(service.logout().get().ok, "logout");
            check(!service.listContacts().get().ok, "logout clears account");
            check(service.login(identity, password).get().ok, "relogin");
            check(service.listHistory(saved).get().rows.size() == 2, "retained native row");
            auto opening = service.login(identity, password);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            service.cancel();
            auto canceled = opening.get();
            check(!canceled.ok && canceled.code == "ACCOUNT_SESSION_CHANGED", "cancel stale login");
        }
        {
            AccountService restarted(path, {}, registry);
            check(restarted.login(identity, password).get().ok, "restart login");
            auto rows = restarted.listHistory("local:saved-messages:v1").get();
            check(rows.ok && rows.rows.size() == 2, "restart same history");
        }
        {
            AccountService noRoot(path);
            auto denied = noRoot.listAccounts().get();
            check(!denied.ok && denied.code == "ROOT_UNLOCK_REQUIRED",
                  "secure registry has no plaintext fallback");
        }
        std::cout << "PASS Account actualJS Argon2d identity; native "
                     "import/login/wrong-password/contacts/Saved history+write/idempotent "
                     "retry/logout/cancel/restart; no fake remote success\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "FAIL " << e.what() << "\n";
        return 1;
    }
}

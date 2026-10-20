// Local owning-profile migration probe. Paths only in argv; credentials only in
// private input files. Operates on NEW target copies and never writes the source.
#include "account_service.h"
#include "broker_service.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <iostream>
#include <openssl/rand.h>
using namespace dmash::account;
static void need(bool b, const char *c) {
    if (!b)
        throw AccountError(c);
}
static QByteArray read(const QString &p) {
    QFile f(p);
    need(f.open(QIODevice::ReadOnly) && f.size() <= 64 * 1024 * 1024, "PROBE_INPUT_FAILED");
    return f.readAll();
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    try {
        need(argc == 4, "USAGE_PROFILE_ACCESS_NEW_PRIVATE_DIRECTORY");
        auto profilePath = QString::fromLocal8Bit(argv[1]),
             accessPath = QString::fromLocal8Bit(argv[2]),
             directory = QString::fromLocal8Bit(argv[3]);
        QDir target(directory);
        need(target.exists(), "PROBE_DIRECTORY_MISSING");
        auto source = read(profilePath),
             sourceDigest = QCryptographicHash::hash(source, QCryptographicHash::Sha256);
        auto profile = QJsonDocument::fromJson(source).object(),
             access = QJsonDocument::fromJson(read(accessPath)).object();
        QByteArray key(32, Qt::Uninitialized);
        need(RAND_bytes(reinterpret_cast<unsigned char *>(key.data()), 32) == 1,
             "PROBE_RANDOM_FAILED");
        QFile keyfile(target.filePath("owner.key"));
        need(keyfile.open(QIODevice::WriteOnly | QIODevice::NewOnly), "PROBE_TARGET_EXISTS");
        need(keyfile.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner) &&
                 keyfile.write(key) == 32 && keyfile.flush(),
             "PROBE_KEY_FAILED");
        keyfile.close();
        dmash::broker::BrokerService broker(target.filePath("credentials.db"), key,
                                            target.filePath("control.db"));
        auto imported =
            broker
                .importProfile(profile, access.value("current_master").toString().toUtf8(),
                               target.filePath("source.backup"))
                .get();
        need(imported.ok && imported.committed, "PROBE_ROOT_IMPORT_FAILED");
        AccountService service(target.filePath("account.db"), {}, [&](const QJsonArray &rows) {
            auto result = broker.readAccountRegistry(rows).get();
            if (!result.ok)
                throw AccountError(result.code.toUtf8().constData());
            return result.accountRegistry;
        });
        auto accountImport = service.importProfile(profile).get();
        need(accountImport.ok && accountImport.importProof.has_value(), "PROBE_ACCOUNT_IMPORT_FAILED");
        need(broker.confirmAccountImport(*accountImport.importProof).get().ok,
             "PROBE_ACCOUNT_ACK_FAILED");
        auto accounts = service.listAccounts().get();
        need(accounts.ok && !accounts.rows.isEmpty(), "PROBE_REGISTRY_FAILED");
        auto identity = access.value("account").toString();
        QJsonObject saved;
        for (auto value : accounts.rows) {
            auto row = value.toObject();
            if (row.value("identity") == identity)
                saved = row;
        }
        need(!saved.isEmpty(), "PROBE_SAVED_ACCOUNT_MISSING");
        auto logged =
            service.login(identity, access.value("account_password").toString().toUtf8()).get();
        need(logged.ok && logged.value.value("accountPublicId") == saved.value("accountPublicId"),
             "PROBE_IDENTITY_MISMATCH");
        const QString local = "local:saved-messages:v1";
        auto before = service.listHistory(local, 0, 100).get();
        need(before.ok && !before.rows.isEmpty(), "PROBE_HISTORY_MISSING");
        auto original = before.rows;
        const auto operation = QString::fromLatin1(
            QCryptographicHash::hash(key + "native-clone-only", QCryptographicHash::Sha256)
                .toHex());
        auto written =
            service.sendText(local, operation, "native retained migration probe (isolated copy)")
                .get();
        need(written.ok && written.value.value("accepted") == true, "PROBE_LOCAL_WRITE_FAILED");
        need(service.logout().get().ok, "PROBE_LOGOUT_FAILED");
        need(service.login(identity, access.value("account_password").toString().toUtf8()).get().ok,
             "PROBE_RELOGIN_FAILED");
        auto after = service.listHistory(local, 0, 100).get();
        need(after.ok && after.rows.size() == original.size() + 1, "PROBE_HISTORY_COUNT");
        for (auto v : original)
            need(after.rows.contains(v), "PROBE_HISTORY_CHANGED");
        need(QCryptographicHash::hash(read(profilePath), QCryptographicHash::Sha256) ==
                 sourceDigest,
             "PROBE_SOURCE_CHANGED");
        QJsonObject report{
            {"ok", true},
            {"scope",
             "native isolated actual retained profile import; no browser/daemon delivery claim"},
            {"sourceSHA256", QString::fromLatin1(sourceDigest.toHex())},
            {"sameAccountPublicId", true},
            {"originalSavedRowsRetained", original.size()},
            {"savedRowsAfterNativeWriteAndRelogin", after.rows.size()},
            {"sourceUnchanged", true},
            {"registryMode", "SECURE"}};
        std::cout << QJsonDocument(report).toJson(QJsonDocument::Compact).constData() << "\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "FAIL " << e.what() << "\n";
        return 1;
    }
}

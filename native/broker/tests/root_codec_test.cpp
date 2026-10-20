#include "root_codec.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QSaveFile>
#include <iostream>
#include <type_traits>
using namespace dmash::broker;
static void check(bool ok) {
    if (!ok)
        throw std::runtime_error("broker assertion failed");
}
template <class F> static void rejects(F f, const char* expected = nullptr) {
    bool failed = false;
    try {
        f();
    } catch (const Error& e) {
        failed = true;
        if (expected)
            check(std::string(e.what()) == expected);
    }
    check(failed);
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        static_assert(!std::is_copy_constructible_v<PreparedRoot>);
        QFile file(BROKER_FIXTURE);
        check(file.open(QIODevice::ReadOnly));
        const auto fixture = QJsonDocument::fromJson(file.readAll()).object(),
                   records = fixture.value("records").toObject();
        const auto pin = fixture.value("pin").toString().toUtf8();
        auto current = [] { return true; };
        for (const auto& name : {"legacy_d", "legacy_id", "modern_id"}) {
            const auto original = records.value(name).toObject();
            auto prepared = RootCodec::openExisting(original, pin, current);
            check(prepared.deviceId() == fixture.value("deviceId"));
            const auto rewritten = RootCodec::prepareRewrap(prepared, "synthetic-only-next-master");
            check(rewritten.value("wrap") == "argon2id-aes-256-gcm-v2");
            check(rewritten.value("materials") == original.value("materials"));
            check(rewritten.value("opaqueMetadata") == original.value("opaqueMetadata"));
            check(rewritten.value("credentialRevision") == original.value("credentialRevision"));
            auto reopened =
                RootCodec::openExisting(rewritten, "synthetic-only-next-master", current);
            check(reopened.deviceId() == prepared.deviceId());
            if (argc >= 2 && QString(name) == "modern_id") {
                QSaveFile exported(QString::fromLocal8Bit(argv[1]));
                check(exported.open(QIODevice::WriteOnly));
                const auto data = QJsonDocument(rewritten).toJson();
                check(exported.write(data) == data.size() && exported.commit());
            }

            if (QString(name) != "modern_id") {
                rejects([&] { RootCodec::existingTransportBundle(reopened, {}, 1, false); },
                        "CREDENTIAL_MIGRATION_REQUIRED");
            } else {
                const auto bundle = RootCodec::existingTransportBundle(reopened, {}, 1, false),
                           expected = fixture.value("expectedTransport").toObject();
                for (auto i = expected.begin(); i != expected.end(); ++i)
                    check(bundle.value(i.key()) == i.value());
                check(bundle.size() == 7 && !bundle.contains("root") && !bundle.contains("pin") &&
                      !bundle.contains("materials"));
            }
        }
        const auto modern = records.value("modern_id").toObject();
        rejects([&] { RootCodec::openExisting({}, pin, current); }, "ROOT_MISSING");
        rejects([&] { RootCodec::openExisting(modern, "wrong-master", current); }, "UNLOCK_FAILED");
        rejects([&] { RootCodec::openExisting(modern, pin, {}); }, "CURRENT_GUARD_REQUIRED");
        bool live = true;
        auto prepared = RootCodec::openExisting(modern, pin, [&] { return live; });
        live = false;
        rejects([&] { prepared.deviceId(); }, "CREDENTIAL_CANCELLED");
        live = true;
        rejects([&] { prepared.deviceId(); }, "CREDENTIAL_CANCELLED");
        int checks = 0;
        rejects([&] { RootCodec::openExisting(modern, pin, [&] { return ++checks < 2; }); },
                "CREDENTIAL_CANCELLED");
        auto policyRoot = RootCodec::openExisting(modern, pin, current);
        rejects(
            [&] {
                RootCodec::existingTransportBundle(
                    policyRoot,
                    QJsonArray{QJsonObject{{"url", "https://example.invalid"},
                                           {"nodeId", QString(64, 'a')}}},
                    1, false);
            },
            "INVALID_TRANSPORT_POLICY");
        rejects([&] { RootCodec::existingTransportBundle(policyRoot, {}, 0, false); },
                "INVALID_TRANSPORT_POLICY");
        for (const auto& state : {"pending-wipe", "cleanup-required"}) {
            auto record = modern;
            auto credentials = record.value("credentials").toObject();
            if (QString(state) == "pending-wipe") {
                credentials["state"] = "pending-wipe";
                credentials.remove("wipe");
                credentials.remove("wipeDisabledReason");
            } else
                credentials["legacyCleanup"] = "required";
            record["credentials"] = credentials;
            auto gated = RootCodec::openExisting(record, pin, current);
            rejects([&] { RootCodec::existingTransportBundle(gated, {}, 1, false); },
                    "CREDENTIAL_MIGRATION_REQUIRED");
        }
        for (const auto& revision :
             QJsonArray{QJsonValue(-1), QJsonValue(9007199254740992.0), QJsonValue("2")}) {
            auto record = modern;
            record["credentialRevision"] = revision;
            rejects([&] { RootCodec::openExisting(record, pin, current); }, "STORAGE_CORRUPT");
        }
        auto invalid = modern;
        invalid["wrapKdf"] = QJsonObject{{"algorithm", "argon2id"}};
        rejects([&] { RootCodec::openExisting(invalid, pin, current); }, "STORAGE_CORRUPT");
        invalid = modern;
        invalid["credentialRevision"] = "2";
        rejects([&] { RootCodec::openExisting(invalid, pin, current); }, "STORAGE_CORRUPT");
        invalid = modern;
        auto c = invalid.value("credentials").toObject();
        c["version"] = 99;
        invalid["credentials"] = c;
        rejects([&] { RootCodec::openExisting(invalid, pin, current); }, "STORAGE_CORRUPT");
        invalid = modern;
        invalid["materials"] = QJsonObject{};
        auto missing = RootCodec::openExisting(invalid, pin, current);
        rejects([&] { RootCodec::existingTransportBundle(missing, {}, 1, false); },
                "NODE_MATERIAL_MISSING");
        auto disposed = RootCodec::openExisting(modern, pin, current);
        disposed.dispose();
        rejects([&] { disposed.deviceId(); }, "CREDENTIAL_CANCELLED");
        const auto fresh = RootCodec::createFreshRecord("synthetic-fresh-master", current);
        auto freshRoot = RootCodec::openExisting(fresh, "synthetic-fresh-master", current);
        check(fresh.value("materials").toObject().size() == 1);
        rejects([&] { RootCodec::existingTransportBundle(freshRoot, {}, 1, false); }, "NODE_MATERIAL_MISSING");
        const QJsonObject publicAccount{{"id", "synthetic-fresh-account"}, {"pk", QString(128, 'a')}, {"displayName", "Fresh test"}};
        const auto registryRow = RootCodec::sealAccountRegistry(freshRoot, publicAccount);
        check(RootCodec::readAccountRegistry(freshRoot, {registryRow}) == QJsonArray{publicAccount});
        if (argc >= 3) {
            QSaveFile exported(QString::fromLocal8Bit(argv[2]));
            check(exported.open(QIODevice::WriteOnly));
            check(exported.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner));
            const auto data = QJsonDocument(QJsonObject{{"record", fresh}, {"deviceId", freshRoot.deviceId()}, {"account", publicAccount}, {"registryRow", registryRow}}).toJson();
            check(exported.write(data) == data.size() && exported.commit());
        }
        std::cout << "PASS native broker legacyD/legacyID/v2 exact JS compatibility; same "
                     "DeviceID/materials; verified rewrap; missingRoot/schema/cancel refusal; "
                     "existing scoped transport only\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << "\n";
        return 1;
    }
}

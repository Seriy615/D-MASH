#include "broker_service.h"
#include "node_miner.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <iostream>
using namespace dmash;
static void need(bool b, const char* c) {
    if (!b)
        throw std::runtime_error(c);
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        QFile f(ACCOUNT_FIXTURE);
        need(f.open(QIODevice::ReadOnly), "fixture");
        auto fixture = QJsonDocument::fromJson(f.readAll()).object();
        auto profile = fixture.value("profile").toObject();
        auto root = profile.value("root").toObject();
        auto materials = root.value("materials").toObject();
        materials.remove("node-ed25519-pow-v4");
        materials.remove("node-base-ncrh-v4");
        root["materials"] = materials;
        profile["root"] = root;
        QTemporaryDir dir(QDir::homePath() +
                          "/.cache/dmash-native-20261020/node-enable-synthetic-XXXXXX");
        need(dir.isValid(), "private dir");
        QFile::setPermissions(dir.path(), QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                              QFileDevice::ExeOwner);
        const auto path = dir.filePath("credentials.db"), control = dir.filePath("control.db");
        const auto pin = fixture.value("rootPin").toString().toUtf8();
        QString nodeId;
        QJsonObject accepted;
        quint64 revision = 0;
        {
            broker::BrokerService broker(path, QByteArray(32, 'n'), control);
            auto imported = broker.importProfile(profile, pin, dir.filePath("source.backup")).get();
            need(imported.ok, "import");
            need(broker.transport({}, false).get().code == "NODE_MATERIAL_MISSING",
                 "no implicit provisioning");
            auto enabled = broker.enableNode(credential::verifyOrMineNodeSeed).get();
            need(enabled.ok && enabled.committed && enabled.deviceId == imported.deviceId,
                 "explicit same Root enable");
            revision = enabled.revision;
            auto bundle = broker.transport({}, false).get();
            need(bundle.ok, "scoped export");
            accepted = bundle.transportBundle;
            auto seed = QByteArray::fromHex(accepted.value("nodeSeed").toString().toLatin1());
            nodeId = credential::nodePublicId(seed);
            need(credential::verifyOrMineNodeSeed(seed, [] { return true; }) == seed,
                 "exact original BLAKE3 proof");
            auto existing = broker.enableNode(credential::verifyOrMineNodeSeed).get();
            need(existing.ok && !existing.committed && existing.revision == revision,
                 "reuse keeps revision/identity");
            auto stopped = broker.fullRootLock().get();
            need(stopped.ok && broker.confirmTransportStopped(stopped.control).get().ok,
                 "no child installed; reserved session stopped");
        }
        {
            broker::BrokerService reopened(path, QByteArray(32, 'n'), control);
            need(reopened.unlock(pin).get().ok, "restart unlock");
            auto bundle = reopened.transport({}, false).get();
            need(bundle.ok, "restart transport");
            for (auto name : {"nodeSeed", "baseNcrh", "storageKey"})
                need(bundle.transportBundle.value(name) == accepted.value(name),
                     "same durable Node material");
        }
        auto store = broker::CredentialStore::openExisting(path, QByteArray(32, 'n'));
        auto state = store->read();
        need(state.root.value("materials").toObject().value("account-registry-v1") ==
                 materials.value("account-registry-v1"),
             "opaque Account registry preserved");
        need(store->exportOriginalProfile() == profile, "original inventory immutable");
        auto replacement = state.root;
        auto changedMaterials = replacement.value("materials").toObject();
        auto changedSeed = changedMaterials.value("node-ed25519-pow-v4").toObject();
        changedSeed["iv"] = QString::fromLatin1(QByteArray(12, 'q').toBase64());
        changedMaterials["node-ed25519-pow-v4"] = changedSeed;
        replacement["materials"] = changedMaterials;
        auto replacementProof =
            broker::RootCodec::openExisting(replacement, pin, [] { return true; });
        bool replaced = false;
        try {
            store->commitNodeEnable(state, replacement, replacementProof, [] { return true; });
        } catch (const broker::Error& e) {
            replaced = std::string(e.what()) == "CREDENTIAL_MATERIAL_CHANGED";
        }
        need(replaced && store->read().root == state.root,
             "existing Node ciphertext cannot be replaced");
        bool cancelled = false;
        try {
            credential::verifyOrMineNodeSeed({}, [] { return false; });
        } catch (const broker::Error& e) {
            cancelled = std::string(e.what()) == "CREDENTIAL_CANCELLED";
        }
        need(cancelled, "cancelled mining");
        bool invalid = false;
        try {
            credential::verifyOrMineNodeSeed(QByteArray(32, 'x'), [] { return true; });
        } catch (const broker::Error& e) {
            invalid = std::string(e.what()) == "NODE_IDENTITY_POW_INVALID";
        }
        need(invalid, "invalid existing refuses replacement");
        std::cout << "PASS explicit first Node enable/reuse/restart/same Root/opaque registry and "
                     "original snapshot; nodeId="
                  << nodeId.toStdString() << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << "\n";
        return 1;
    }
}

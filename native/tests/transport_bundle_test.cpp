#include "transport_bundle.h"
#include <QCoreApplication>
#include <QJsonArray>
#include <iostream>
#include <stdexcept>
static QJsonObject bundle() {
    return {{"version", 1},
            {"nodeSeed", QString(64, 'a')},
            {"storageKey", QString(64, 'b')},
            {"baseNcrh", QString(64, 'c')},
            {"generation", 1},
            {"directEnabled", false},
            {"endpoints", QJsonArray{QJsonObject{{"url", "wss://example.invalid/node"},
                                                 {"nodeId", QString(64, 'd')}}}}};
}
static void require(bool ok) {
    if (!ok)
        throw std::runtime_error("bundle assertion failed");
}
static void rejects(const QJsonObject& o) {
    bool rejected = false;
    try {
        auto b = dmash::TransportBundle::parse(o);
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected);
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        auto original = bundle();
        auto b = dmash::TransportBundle::parse(original);
        require(b.nodeSeed.size() == 32 && b.generation == 1 && !b.directEnabled &&
                b.endpoints.size() == 1);
        for (const auto& field : {"root", "pin", "accountKey", "callback", "deviceMaterial"}) {
            auto bad = original;
            bad.insert(field, "forbidden");
            rejects(bad);
        }
        for (const auto& field : {"nodeSeed", "storageKey", "baseNcrh"}) {
            auto bad = original;
            bad.insert(field, QString(62, 'a'));
            rejects(bad);
            bad.insert(field, QString(64, 'A'));
            rejects(bad);
        }
        for (const auto& url :
             {"ws://example.invalid/node", "wss://user:password@example.invalid/node",
              "wss://example.invalid/node#fragment", "file:///tmp/not-an-endpoint",
              "wss:///missing-host"}) {
            auto bad = original;
            bad["endpoints"] = QJsonArray{QJsonObject{{"url", url}, {"nodeId", QString(64, 'd')}}};
            rejects(bad);
        }
        for (const double gen : {0., -1., 1.5, 9007199254740992.}) {
            auto bad = original;
            bad["generation"] = gen;
            rejects(bad);
        }
        auto bad = original;
        bad["directEnabled"] = 1;
        rejects(bad);
        bad = original;
        bad["endpoints"] =
            QJsonArray{original["endpoints"].toArray()[0], original["endpoints"].toArray()[0]};
        rejects(bad);
        auto moved = std::move(b);
        require(moved.nodeSeed.size() == 32 && b.nodeSeed.isEmpty());
        moved.clear();
        require(moved.nodeSeed.isEmpty() && moved.storageKey.isEmpty() && moved.baseNcrh.isEmpty());
        std::cout << "PASS strict scoped bundle rejects Account/root/PIN/URL scope and malformed "
                     "generations\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}

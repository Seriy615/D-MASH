#include "transport_bundle.h"
#include <QJsonArray>
#include <QRegularExpression>
#include <QSet>
#include <openssl/crypto.h>
#include <stdexcept>
namespace dmash {
TransportBundle::TransportBundle(TransportBundle&& other) noexcept { *this = std::move(other); }
TransportBundle& TransportBundle::operator=(TransportBundle&& other) noexcept {
    if (this != &other) {
        clear();
        nodeSeed = std::move(other.nodeSeed);
        storageKey = std::move(other.storageKey);
        baseNcrh = std::move(other.baseNcrh);
        endpoints = std::move(other.endpoints);
        generation = other.generation;
        directEnabled = other.directEnabled;
        other.generation = 0;
        other.directEnabled = false;
    }
    return *this;
}
TransportBundle::~TransportBundle() { clear(); }
static void require(bool ok) {
    if (!ok)
        throw std::runtime_error("Invalid scoped transport bundle");
}
static void fields(const QJsonObject& o, const QStringList& keys) {
    QSet<QString> got, want;
    for (auto i = o.begin(); i != o.end(); ++i)
        got.insert(i.key());
    for (const auto& k : keys)
        want.insert(k);
    require(got == want);
}
static QByteArray hex32(const QJsonValue& v) {
    require(v.isString());
    const auto s = v.toString();
    require(QRegularExpression("^[0-9a-f]{64}$").match(s).hasMatch());
    return QByteArray::fromHex(s.toLatin1());
}
TransportBundle TransportBundle::parse(const QJsonObject& o) {
    fields(o, {"version", "nodeSeed", "storageKey", "baseNcrh", "generation", "directEnabled",
               "endpoints"});
    require(o.value("version").isDouble() && o.value("version").toDouble() == 1);
    require(o.value("generation").isDouble());
    const double gen = o.value("generation").toDouble();
    require(gen >= 1 && gen <= 9007199254740991.0 && double(quint64(gen)) == gen);
    require(o.value("directEnabled").isBool());
    require(o.value("endpoints").isArray());
    const auto list = o.value("endpoints").toArray();
    require(list.size() <= 8);
    TransportBundle b;
    try {
        b.nodeSeed = hex32(o.value("nodeSeed"));
        b.storageKey = hex32(o.value("storageKey"));
        b.baseNcrh = hex32(o.value("baseNcrh"));
        b.generation = quint64(gen);
        b.directEnabled = o.value("directEnabled").toBool();
        QSet<QString> seen;
        for (const auto& item : list) {
            require(item.isObject());
            const auto e = item.toObject();
            fields(e, {"url", "nodeId"});
            require(e.value("url").isString());
            const auto text = e.value("url").toString();
            require(text.size() <= 2048);
            const QUrl url(text, QUrl::StrictMode);
            require(url.isValid() && !url.isRelative() && !url.host().isEmpty() &&
                    url.userInfo().isEmpty() && !url.hasFragment());
            require(url.scheme() == "wss" ||
                    (url.scheme() == "ws" && (url.host() == "127.0.0.1" ||
                                              url.host() == "localhost" || url.host() == "::1")));
            const auto node = hex32(e.value("nodeId"));
            const auto id = QString::fromLatin1(node.toHex());
            const auto endpointKey = id + QChar(0) + url.toString(QUrl::FullyEncoded);
            require(!seen.contains(endpointKey));
            seen.insert(endpointKey);
            b.endpoints.append({url, id});
        }
        return b;
    } catch (...) {
        b.clear();
        throw;
    }
}
void TransportBundle::clear() {
    for (auto* p : {&nodeSeed, &storageKey, &baseNcrh}) {
        p->detach();
        if (!p->isEmpty())
            OPENSSL_cleanse(p->data(), size_t(p->size()));
        p->clear();
    }
    endpoints.clear();
    generation = 0;
    directEnabled = false;
}
} // namespace dmash

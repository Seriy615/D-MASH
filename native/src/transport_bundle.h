#pragma once
#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <QUrl>
#include <QVector>
namespace dmash {
// Input from a separate credential broker. Contains transport scope only.
struct EndpointGrant {
    QUrl url;
    QString nodeId;
};
struct TransportBundle {
    TransportBundle() = default;
    TransportBundle(const TransportBundle&) = delete;
    TransportBundle& operator=(const TransportBundle&) = delete;
    TransportBundle(TransportBundle&&) noexcept;
    TransportBundle& operator=(TransportBundle&&) noexcept;
    ~TransportBundle();
    QByteArray nodeSeed, storageKey, baseNcrh;
    QVector<EndpointGrant> endpoints;
    quint64 generation = 0;
    bool directEnabled = false;
    static TransportBundle parse(const QJsonObject&);
    void clear();
};
} // namespace dmash

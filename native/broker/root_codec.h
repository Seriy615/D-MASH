#pragma once
#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QString>
#include <functional>
#include <memory>
#include <stdexcept>
#include <utility>

namespace dmash::broker {
class Error final : public std::runtime_error {
  public:
    explicit Error(const char* code) : std::runtime_error(code) {}
};
// In-process broker-only handle. No root bytes, arbitrary material aliases,
// Account keys or serialization are exposed by this API.
class PreparedRoot final {
  public:
    PreparedRoot(PreparedRoot&&) noexcept;
    PreparedRoot& operator=(PreparedRoot&&) noexcept;
    ~PreparedRoot();
    PreparedRoot(const PreparedRoot&) = delete;
    PreparedRoot& operator=(const PreparedRoot&) = delete;
    QString deviceId() const;
    bool matchesRecord(const QJsonObject&) const;
    void dispose();

  private:
    friend class RootCodec;
    struct State;
    explicit PreparedRoot(std::unique_ptr<State>);
    std::unique_ptr<State> state_;
};
// Compatibility primitive, NOT a credential store/coordinator or network API.
// All record arguments/results contain encrypted material only. The owning
// service must supply cancellation/session fencing and atomic store CAS.
class RootCodec final {
  public:
    using Current = std::function<bool()>;
    static PreparedRoot openExisting(const QJsonObject& encryptedRecord, const QByteArray& pinUtf8,
                                     Current current);
    // Produces verified wrap fields merged into an unchanged encrypted record;
    // does not commit, publish, change revision, migrate wipe or clean legacy DBs.
    // Account-owner only. Authenticates existing secure registry rows; never exports its key.
    static QJsonArray readAccountRegistry(PreparedRoot&, const QJsonArray& encryptedRows);
    static QJsonObject wipeVerifier(const QByteArray& pinUtf8, Current current);
    static QJsonObject prepareRewrap(PreparedRoot&, const QByteArray& newPinUtf8);
    // Only existing named Node slots can leave the broker. Missing slots fail;
    // this function cannot mint a replacement Node identity or arbitrary alias.
    // Actor must still verify Node work/authentication and endpoint grants.
    using NodeSeedFactory = std::function<QByteArray(const QByteArray& existingSeed, Current)>;
    // Explicit owner enable only. Factory verifies/reuses existing seed or mines a new one.
    // Existing authenticated Node slots are never replaced, including partial provisioning.
    static std::pair<PreparedRoot, QJsonObject> prepareNodeEnable(PreparedRoot&, NodeSeedFactory);
    static QJsonObject existingTransportBundle(PreparedRoot&, const QJsonArray& endpointGrants,
                                               quint64 generation, bool directEnabled);
};
} // namespace dmash::broker

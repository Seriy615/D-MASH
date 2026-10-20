#include "root_codec.h"
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSet>
#include <QUrl>
#include <QtEndian>
#include <cmath>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
namespace dmash::broker {
namespace {
void require(bool ok, const char* code = "STORAGE_CORRUPT") {
    if (!ok)
        throw Error(code);
}
class Secret {
  public:
    QByteArray bytes;
    explicit Secret(QByteArray value = {}) : bytes(std::move(value)) { bytes.detach(); }
    ~Secret() { clear(); }
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    void clear() {
        if (!bytes.isEmpty())
            OPENSSL_cleanse(bytes.data(), size_t(bytes.size()));
        bytes.clear();
    }
};
QByteArray decode(const QJsonValue& value, int length) {
    require(value.isString());
    const auto text = value.toString().toLatin1();
    const auto bytes = QByteArray::fromBase64(text, QByteArray::AbortOnBase64DecodingErrors);
    require(bytes.size() == length && bytes.toBase64() == text);
    return bytes;
}
QJsonObject profile() {
    return {{"algorithm", "argon2id"},
            {"version", 19},
            {"type", 2},
            {"time", 3},
            {"mem", 65536},
            {"parallelism", 1},
            {"hashLen", 32},
            {"saltEncoding", "base64-utf8"}};
}
void only(const QJsonObject& o, const QSet<QString>& keys) {
    for (auto i = o.begin(); i != o.end(); ++i)
        require(keys.contains(i.key()));
}
void validate(const QJsonObject& record) {
    require(!record.isEmpty(), "ROOT_MISSING");
    require(record.value("id") == "root" && record.value("version") == 1);
    const auto rev = record.value("credentialRevision");
    if (!rev.isUndefined())
        require(rev.isDouble() && std::isfinite(rev.toDouble()) && rev.toDouble() >= 0 &&
                rev.toDouble() <= 9007199254740991.0 &&
                std::floor(rev.toDouble()) == rev.toDouble());
    const auto value = record.value("credentials");
    if (value.isUndefined())
        return;
    require(value.isObject());
    const auto c = value.toObject();
    only(c, {"version", "state", "legacyCleanup", "wipe", "wipeDisabledReason"});
    const auto state = c.value("state").toString(), cleanup = c.value("legacyCleanup").toString();
    require(c.value("version") == 1 && (state == "ready" || state == "pending-wipe") &&
            (cleanup == "required" || cleanup == "complete") && rev.toDouble() >= 1);
    if (state == "pending-wipe") {
        require(c.value("wipe").isUndefined() && cleanup == "complete" &&
                c.value("wipeDisabledReason").isUndefined());
        return;
    }
    const auto w = c.value("wipe");
    require(!w.isUndefined());
    if (w.isNull()) {
        require(c.value("wipeDisabledReason") == "legacy-collision" ||
                c.value("wipeDisabledReason") == "not-configured");
        return;
    }
    require(w.isObject());
    const auto obj = w.toObject();
    only(obj, {"profile", "salt", "digest"});
    require(obj.value("profile") == "sha256-prehash-argon2id-v1");
    require(c.value("wipeDisabledReason").isUndefined() || c.value("wipeDisabledReason").isNull());
    decode(obj.value("salt"), 16);
    decode(obj.value("digest"), 32);
}
QByteArray argon(const QByteArray& pin, const QByteArray& rawSalt, bool id,
                 bool literalSalt = false) {
    require(!pin.isEmpty() && pin.size() <= 4096, "MASTER_PIN_REQUIRED");
    // The deployed JS passes UTF8(base64(random16)); raw salt bytes are NOT used.
    auto salt = literalSalt ? rawSalt : rawSalt.toBase64();
    uint32_t lanes = 1, threads = 1, iter = 3, mem = 65536, version = 19;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                          const_cast<char*>(pin.constData()), size_t(pin.size())),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), size_t(salt.size())),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version),
        OSSL_PARAM_END};
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(
        EVP_KDF_fetch(nullptr, id ? "ARGON2ID" : "ARGON2D", nullptr), EVP_KDF_free);
    require(bool(kdf), "ARGON2_UNAVAILABLE");
    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> ctx(EVP_KDF_CTX_new(kdf.get()),
                                                                  EVP_KDF_CTX_free);
    require(bool(ctx), "ARGON2_FAILED");
    Secret out(QByteArray(32, Qt::Uninitialized));
    require(EVP_KDF_derive(ctx.get(), reinterpret_cast<unsigned char*>(out.bytes.data()), 32,
                           params) > 0,
            "ARGON2_FAILED");
    return std::move(out.bytes);
}
QByteArray gcm(bool encrypt, const QByteArray& key, const QByteArray& iv, const QByteArray& aad,
               const QByteArray& bytes) {
    require(key.size() == 32 && iv.size() == 12);
    require(bytes.size() < 16 * 1024 * 1024 && (encrypt || bytes.size() >= 16));
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(),
                                                                        EVP_CIPHER_CTX_free);
    require(bool(ctx), "CRYPTO_FAILED");
    require(EVP_CipherInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr,
                              encrypt ? 1 : 0) == 1,
            "CRYPTO_FAILED");
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1,
            "CRYPTO_FAILED");
    require(EVP_CipherInit_ex(ctx.get(), nullptr, nullptr,
                              reinterpret_cast<const unsigned char*>(key.constData()),
                              reinterpret_cast<const unsigned char*>(iv.constData()),
                              encrypt ? 1 : 0) == 1,
            "CRYPTO_FAILED");
    int n = 0;
    require(EVP_CipherUpdate(ctx.get(), nullptr, &n,
                             reinterpret_cast<const unsigned char*>(aad.constData()),
                             aad.size()) == 1,
            "CRYPTO_FAILED");
    const int length = bytes.size() - (encrypt ? 0 : 16);
    Secret out(QByteArray(length + 16, Qt::Uninitialized));
    require(EVP_CipherUpdate(ctx.get(), reinterpret_cast<unsigned char*>(out.bytes.data()), &n,
                             reinterpret_cast<const unsigned char*>(bytes.constData()),
                             length) == 1,
            "CRYPTO_FAILED");
    int total = n;
    if (!encrypt)
        require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                                    const_cast<char*>(bytes.constData() + length)) == 1,
                "CRYPTO_FAILED");
    require(EVP_CipherFinal_ex(ctx.get(),
                               reinterpret_cast<unsigned char*>(out.bytes.data()) + total, &n) == 1,
            "UNLOCK_FAILED");
    total += n;
    if (encrypt) {
        require(
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, out.bytes.data() + total) == 1,
            "CRYPTO_FAILED");
        total += 16;
    }
    out.bytes.resize(total);
    return std::move(out.bytes);
}
QByteArray info(const QByteArray& domain, quint32 version, const QByteArray& context) {
    QByteArray out;
    auto add = [&](quint32 n) {
        char b[4];
        qToBigEndian(n, b);
        out.append(b, 4);
    };
    add(version);
    add(domain.size());
    out += domain;
    add(context.size());
    out += context;
    return out;
}
QByteArray derive(const QByteArray& root, const QByteArray& domain, quint32 version = 1,
                  const QByteArray& context = {}) {
    require(root.size() == 32);
    QByteArray salt(32, 0), i = info(domain, version, context);
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<char*>(root.constData()),
                                          32),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), 32),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, i.data(), i.size()), OSSL_PARAM_END};
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr),
                                                          EVP_KDF_free);
    require(bool(kdf), "CRYPTO_FAILED");
    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> ctx(EVP_KDF_CTX_new(kdf.get()),
                                                                  EVP_KDF_CTX_free);
    require(bool(ctx), "CRYPTO_FAILED");
    Secret out(QByteArray(32, Qt::Uninitialized));
    require(EVP_KDF_derive(ctx.get(), reinterpret_cast<unsigned char*>(out.bytes.data()), 32,
                           params) > 0,
            "CRYPTO_FAILED");
    return std::move(out.bytes);
}
QByteArray publicKey(const char* type, const QByteArray& seed) {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_new_raw_private_key_ex(nullptr, type, nullptr,
                                        reinterpret_cast<const unsigned char*>(seed.constData()),
                                        seed.size()),
        EVP_PKEY_free);
    require(bool(key), "CRYPTO_FAILED");
    QByteArray out(32, Qt::Uninitialized);
    size_t n = 32;
    require(EVP_PKEY_get_raw_public_key(key.get(), reinterpret_cast<unsigned char*>(out.data()),
                                        &n) == 1 &&
                n == 32,
            "CRYPTO_FAILED");
    return out;
}
QString identity(const QByteArray& root) {
    Secret ed(derive(root, "dmash/device-identity-ed25519")),
        x(derive(root, "dmash/device-identity-x25519"));
    const auto bytes = QByteArray("dmash/device-id/v1") + publicKey("ED25519", ed.bytes) +
                       publicKey("X25519", x.bytes);
    return "d1_" + QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256)
                                           .toBase64(QByteArray::Base64UrlEncoding |
                                                     QByteArray::OmitTrailingEquals));
}
QByteArray open(const QJsonObject& record, const QByteArray& pin,
                const RootCodec::Current& current) {
    require(current && current(), "CREDENTIAL_CANCELLED");
    validate(record);
    const bool modern = record.value("wrap") == "argon2id-aes-256-gcm-v2";
    if (modern)
        require(record.value("wrapKdf").isObject() &&
                record.value("wrapKdf").toObject() == profile());
    else
        require(record.value("wrap").isUndefined() ||
                record.value("wrap") == "argon2id-aes-256-gcm-v1");
    const auto salt = decode(record.value("wrapSalt"), 16), iv = decode(record.value("iv"), 12),
               wrapped = decode(record.value("wrappedRoot"), 48);
    for (int attempt = modern ? 1 : 0; attempt < 2; ++attempt) {
        Secret key(argon(pin, salt, attempt == 1));
        require(current(), "CREDENTIAL_CANCELLED");
        try {
            Secret root(gcm(false, key.bytes, iv,
                            modern ? "dmash/device-root-wrap/v2" : "dmash/device-root-wrap/v1",
                            wrapped));
            require(root.bytes.size() == 32);
            require(current(), "CREDENTIAL_CANCELLED");
            return std::move(root.bytes);
        } catch (const Error& e) {
            if (std::string(e.what()) != "UNLOCK_FAILED" || attempt == 1)
                throw;
        }
    }
    throw Error("UNLOCK_FAILED");
}
QByteArray random(int n) {
    QByteArray out(n, Qt::Uninitialized);
    require(RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), n) == 1, "CRYPTO_FAILED");
    return out;
}
} // namespace
struct PreparedRoot::State {
    Secret root;
    QJsonObject record;
    QString id;
    RootCodec::Current current;
    State(QByteArray r, QJsonObject o, RootCodec::Current c)
        : root(std::move(r)), record(std::move(o)), id(identity(root.bytes)),
          current(std::move(c)) {}
    void check() {
        if (!current || !current() || root.bytes.size() != 32) {
            root.clear();
            throw Error("CREDENTIAL_CANCELLED");
        }
    }
};
PreparedRoot::PreparedRoot(std::unique_ptr<State> state) : state_(std::move(state)) {}
PreparedRoot::PreparedRoot(PreparedRoot&&) noexcept = default;
PreparedRoot& PreparedRoot::operator=(PreparedRoot&&) noexcept = default;
PreparedRoot::~PreparedRoot() = default;
QString PreparedRoot::deviceId() const {
    require(bool(state_), "CREDENTIAL_CANCELLED");
    state_->check();
    return state_->id;
}
bool PreparedRoot::matchesRecord(const QJsonObject& record) const {
    require(bool(state_), "CREDENTIAL_CANCELLED");
    state_->check();
    auto a = state_->record, b = record;
    a.remove("credentialRevision");
    b.remove("credentialRevision");
    return a == b;
}
void PreparedRoot::dispose() { state_.reset(); }
PreparedRoot RootCodec::openExisting(const QJsonObject& record, const QByteArray& pin,
                                     Current current) {
    require(bool(current), "CURRENT_GUARD_REQUIRED");
    require(QJsonDocument(record).toJson(QJsonDocument::Compact).size() <= 16 * 1024 * 1024);
    Secret root(open(record, pin, current));
    auto state =
        std::make_unique<PreparedRoot::State>(std::move(root.bytes), record, std::move(current));
    state->check();
    return PreparedRoot(std::move(state));
}
QJsonObject RootCodec::createFreshRecord(const QByteArray& pin, Current current) {
    require(current && current(), "CREDENTIAL_CANCELLED");
    Secret root(random(32)), registry(random(32));
    const QByteArray name("account-registry-v1");
    Secret wrapping(derive(root.bytes, "dmash/device-mlkem-seed-root", 1, name));
    const auto iv = random(12);
    QJsonObject record{
        {"id", "root"},
        {"version", 1},
        {"credentialRevision", 1},
        {"credentials", QJsonObject{{"version", 1},
                                    {"state", "ready"},
                                    {"legacyCleanup", "complete"},
                                    {"wipe", QJsonValue::Null},
                                    {"wipeDisabledReason", "not-configured"}}},
        {"materials",
         QJsonObject{
             {QString::fromLatin1(name),
              QJsonObject{{"iv", QString::fromLatin1(iv.toBase64())},
                          {"ciphertext", QString::fromLatin1(gcm(true, wrapping.bytes, iv,
                                                                 "dmash/device-material/v1|" + name,
                                                                 registry.bytes)
                                                                 .toBase64())}}}}}};
    PreparedRoot prepared(
        std::make_unique<PreparedRoot::State>(std::move(root.bytes), record, current));
    return prepareRewrap(prepared, pin);
}
QJsonObject RootCodec::sealAccountRegistry(PreparedRoot& prepared, const QJsonObject& account) {
    require(bool(prepared.state_), "ROOT_UNLOCK_REQUIRED");
    auto& s = *prepared.state_;
    s.check();
    only(account, {"id", "pk", "displayName"});
    const auto id = account.value("id").toString();
    require(!id.isEmpty() && id.toUtf8().size() <= 128 && id.trimmed() == id &&
                QRegularExpression("^[0-9a-f]{128}$")
                    .match(account.value("pk").toString())
                    .hasMatch() &&
                account.value("displayName").toString().toUtf8().size() <= 256,
            "ACCOUNT_CREATE_INPUT");
    const QByteArray name("account-registry-v1");
    const auto material =
        s.record.value("materials").toObject().value(QString::fromLatin1(name)).toObject();
    require(!material.isEmpty(), "ACCOUNT_REGISTRY_MATERIAL_MISSING");
    Secret wrapping(derive(s.root.bytes, "dmash/device-mlkem-seed-root", 1, name));
    Secret registry(gcm(false, wrapping.bytes, decode(material.value("iv"), 12),
                        "dmash/device-material/v1|" + name,
                        decode(material.value("ciphertext"), 48)));
    // Alias is exactly the existing registry HMAC-SHA256(identity UTF8).
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr),
                                                          EVP_MAC_free);
    require(bool(mac), "CRYPTO_FAILED");
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(EVP_MAC_CTX_new(mac.get()),
                                                                  EVP_MAC_CTX_free);
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
                           OSSL_PARAM_END};
    QByteArray hash(32, Qt::Uninitialized);
    const auto identity = id.toUtf8();
    size_t length = 0;
    require(bool(ctx) &&
                EVP_MAC_init(ctx.get(),
                             reinterpret_cast<const unsigned char*>(registry.bytes.constData()), 32,
                             params) == 1 &&
                EVP_MAC_update(ctx.get(),
                               reinterpret_cast<const unsigned char*>(identity.constData()),
                               size_t(identity.size())) == 1 &&
                EVP_MAC_final(ctx.get(), reinterpret_cast<unsigned char*>(hash.data()), &length,
                              32) == 1 &&
                length == 32,
            "CRYPTO_FAILED");
    const auto iv = random(12);
    Secret plain(QJsonDocument(account).toJson(QJsonDocument::Compact));
    const auto blob = iv + gcm(true, registry.bytes, iv, "dmash/account-registry/v1", plain.bytes);
    QJsonObject row{{"alias", QString::fromLatin1(hash.toBase64())},
                    {"blob", QString::fromLatin1(blob.toBase64())}};
    require(readAccountRegistry(prepared, QJsonArray{row}) == QJsonArray{account},
            "ACCOUNT_REGISTRY_VERIFY_FAILED");
    s.check();
    return row;
}
QJsonObject RootCodec::prepareRewrap(PreparedRoot& prepared, const QByteArray& pin) {
    require(bool(prepared.state_), "CREDENTIAL_CANCELLED");
    auto& s = *prepared.state_;
    s.check();
    const auto salt = random(16), iv = random(12);
    Secret key(argon(pin, salt, true));
    s.check();
    auto result = s.record;
    result["wrap"] = "argon2id-aes-256-gcm-v2";
    result["wrapKdf"] = profile();
    result["wrapSalt"] = QString::fromLatin1(salt.toBase64());
    result["iv"] = QString::fromLatin1(iv.toBase64());
    result["wrappedRoot"] = QString::fromLatin1(
        gcm(true, key.bytes, iv, "dmash/device-root-wrap/v2", s.root.bytes).toBase64());
    Secret reopened(open(result, pin, s.current));
    s.check();
    require(reopened.bytes.size() == 32 &&
                CRYPTO_memcmp(reopened.bytes.constData(), s.root.bytes.constData(), 32) == 0,
            "WRAP_VERIFY_FAILED");
    return result;
}
QJsonArray RootCodec::readAccountRegistry(PreparedRoot& prepared, const QJsonArray& rows) {
    require(bool(prepared.state_), "CREDENTIAL_CANCELLED");
    auto& s = *prepared.state_;
    s.check();
    require(rows.size() <= 1024, "ACCOUNT_REGISTRY_LIMIT");
    const QString name = "account-registry-v1";
    const auto slot = s.record.value("materials").toObject().value(name);
    require(slot.isObject(), "ACCOUNT_REGISTRY_MATERIAL_MISSING");
    const auto material = slot.toObject();
    Secret wrapping(derive(s.root.bytes, "dmash/device-mlkem-seed-root", 1, name.toUtf8()));
    Secret registry(gcm(false, wrapping.bytes, decode(material.value("iv"), 12),
                        "dmash/device-material/v1|" + name.toUtf8(),
                        decode(material.value("ciphertext"), 48)));
    QJsonArray result;
    QSet<QString> aliases;
    for (const auto& value : rows) {
        s.check();
        require(value.isObject(), "ACCOUNT_REGISTRY_CORRUPT");
        const auto row = value.toObject();
        require(row.value("alias").isString() && row.value("blob").isString() &&
                    row.value("blob").toString().size() <= 131072,
                "ACCOUNT_REGISTRY_CORRUPT");
        const auto encoded = row.value("blob").toString().toLatin1();
        const auto packed =
            QByteArray::fromBase64(encoded, QByteArray::AbortOnBase64DecodingErrors);
        require(packed.size() >= 28 && packed.toBase64() == encoded, "ACCOUNT_REGISTRY_CORRUPT");
        Secret plain(gcm(false, registry.bytes, packed.left(12), "dmash/account-registry/v1",
                         packed.mid(12)));
        QJsonParseError error;
        auto doc = QJsonDocument::fromJson(plain.bytes, &error);
        require(error.error == QJsonParseError::NoError && doc.isObject(),
                "ACCOUNT_REGISTRY_CORRUPT");
        const auto account = doc.object();
        require(account.value("id").isString() && !account.value("id").toString().isEmpty(),
                "ACCOUNT_REGISTRY_CORRUPT");
        auto id = account.value("id").toString().toUtf8();
        std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(
            EVP_MAC_fetch(nullptr, "HMAC", nullptr), EVP_MAC_free);
        require(bool(mac), "CRYPTO_FAILED");
        std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(EVP_MAC_CTX_new(mac.get()),
                                                                      EVP_MAC_CTX_free);
        char digest[] = "SHA256";
        OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
                               OSSL_PARAM_END};
        QByteArray hash(32, Qt::Uninitialized);
        size_t length = 0;
        require(bool(ctx) &&
                    EVP_MAC_init(ctx.get(),
                                 reinterpret_cast<const unsigned char*>(registry.bytes.constData()),
                                 32, params) == 1 &&
                    EVP_MAC_update(ctx.get(),
                                   reinterpret_cast<const unsigned char*>(id.constData()),
                                   id.size()) == 1 &&
                    EVP_MAC_final(ctx.get(), reinterpret_cast<unsigned char*>(hash.data()), &length,
                                  32) == 1 &&
                    length == 32,
                "CRYPTO_FAILED");
        const auto expected = QString::fromLatin1(hash.toBase64());
        require(row.value("alias").toString() == expected && !aliases.contains(expected),
                "ACCOUNT_REGISTRY_CORRUPT");
        aliases.insert(expected);
        result.append(account);
    }
    s.check();
    return result;
}
QJsonObject RootCodec::wipeVerifier(const QByteArray& pin, Current current) {
    require(current && current(), "CREDENTIAL_CANCELLED");
    require(!pin.isEmpty() && pin.size() <= 4096, "INVALID_LOCAL_PIN");
    Secret prehash(QCryptographicHash::hash(pin, QCryptographicHash::Sha256).toHex());
    const auto salt = random(16).toBase64();
    Secret digest(argon(prehash.bytes, "dmash/local-wipe/v1|" + salt, true, true));
    require(current(), "CREDENTIAL_CANCELLED");
    return {{"profile", "sha256-prehash-argon2id-v1"},
            {"salt", QString::fromLatin1(salt)},
            {"digest", QString::fromLatin1(digest.bytes.toBase64())}};
}
std::pair<PreparedRoot, QJsonObject> RootCodec::prepareNodeEnable(PreparedRoot& prepared,
                                                                  NodeSeedFactory factory) {
    require(bool(prepared.state_) && bool(factory), "ROOT_UNLOCK_REQUIRED");
    auto& s = *prepared.state_;
    s.check();
    auto record = s.record;
    auto materials = record.value("materials").toObject();
    auto read = [&](const QString& name) {
        const auto item = materials.value(name);
        if (item.isUndefined())
            return QByteArray{};
        require(item.isObject(), "NODE_MATERIAL_CORRUPT");
        Secret key(derive(s.root.bytes, "dmash/device-mlkem-seed-root", 1, name.toUtf8()));
        const auto slot = item.toObject();
        return gcm(false, key.bytes, decode(slot.value("iv"), 12),
                   "dmash/device-material/v1|" + name.toUtf8(),
                   decode(slot.value("ciphertext"), 48));
    };
    Secret existing(read("node-ed25519-pow-v4"));
    Secret seed(factory(existing.bytes, s.current));
    s.check();
    require(seed.bytes.size() == 32 && (existing.bytes.isEmpty() || existing.bytes == seed.bytes),
            "NODE_IDENTITY_REPLACEMENT_REFUSED");
    Secret ncrh(read("node-base-ncrh-v4"));
    if (ncrh.bytes.isEmpty())
        ncrh.bytes = random(32);
    auto append = [&](const QString& name, const QByteArray& bytes) {
        if (materials.contains(name))
            return;
        Secret key(derive(s.root.bytes, "dmash/device-mlkem-seed-root", 1, name.toUtf8()));
        const auto iv = random(12);
        materials[name] =
            QJsonObject{{"iv", QString::fromLatin1(iv.toBase64())},
                        {"ciphertext",
                         QString::fromLatin1(gcm(true, key.bytes, iv,
                                                 "dmash/device-material/v1|" + name.toUtf8(), bytes)
                                                 .toBase64())}};
    };
    append("node-ed25519-pow-v4", seed.bytes);
    append("node-base-ncrh-v4", ncrh.bytes);
    record["materials"] = materials;
    s.check();
    PreparedRoot proof(std::make_unique<PreparedRoot::State>(s.root.bytes, record, s.current));
    require(proof.deviceId() == s.id, "CREDENTIAL_BINDING_INVALID");
    return {std::move(proof), record};
}
QJsonObject RootCodec::existingTransportBundle(PreparedRoot& prepared, const QJsonArray& endpoints,
                                               quint64 generation, bool direct) {
    require(bool(prepared.state_), "CREDENTIAL_CANCELLED");
    auto& s = *prepared.state_;
    s.check();
    const auto credentials = s.record.value("credentials").toObject();
    require(credentials.value("state") == "ready" &&
                credentials.value("legacyCleanup") == "complete",
            "CREDENTIAL_MIGRATION_REQUIRED");
    require(generation >= 1 && generation <= 9007199254740991ULL && endpoints.size() <= 8,
            "INVALID_TRANSPORT_POLICY");
    // Structural endpoint validation is repeated independently by the actor.
    QSet<QString> seen;
    for (const auto& v : endpoints) {
        require(v.isObject(), "INVALID_TRANSPORT_POLICY");
        auto o = v.toObject();
        require(o.size() == 2 && o.contains("url") && o.contains("nodeId"),
                "INVALID_TRANSPORT_POLICY");
        require(
            o.value("url").isString() && o.value("url").toString().size() <= 2048 &&
                QRegularExpression("^[0-9a-f]{64}$").match(o.value("nodeId").toString()).hasMatch(),
            "INVALID_TRANSPORT_POLICY");
        const QUrl url(o.value("url").toString(), QUrl::StrictMode);
        require(url.isValid() && !url.isRelative() && !url.host().isEmpty() &&
                    url.userInfo().isEmpty() && !url.hasFragment() &&
                    (url.scheme() == "wss" ||
                     (url.scheme() == "ws" && (url.host() == "127.0.0.1" ||
                                               url.host() == "localhost" || url.host() == "::1"))),
                "INVALID_TRANSPORT_POLICY");
        const auto scope =
            o.value("nodeId").toString() + QChar(0) + url.toString(QUrl::FullyEncoded);
        require(!seen.contains(scope), "INVALID_TRANSPORT_POLICY");
        seen.insert(scope);
    }
    auto material = [&](const QString& name) {
        s.check();
        const auto m = s.record.value("materials").toObject().value(name);
        require(m.isObject(), "NODE_MATERIAL_MISSING");
        const auto o = m.toObject();
        Secret key(derive(s.root.bytes, "dmash/device-mlkem-seed-root", 1, name.toUtf8()));
        Secret value(gcm(false, key.bytes, decode(o.value("iv"), 12),
                         "dmash/device-material/v1|" + name.toUtf8(),
                         decode(o.value("ciphertext"), 48)));
        s.check();
        require(value.bytes.size() == 32);
        return std::move(value.bytes);
    };
    Secret seed(material("node-ed25519-pow-v4")), ncrh(material("node-base-ncrh-v4")),
        storage(derive(s.root.bytes, "dmash/node-storage", 4, "directional-relationships"));
    s.check();
    return {{"version", 1},
            {"nodeSeed", QString::fromLatin1(seed.bytes.toHex())},
            {"storageKey", QString::fromLatin1(storage.bytes.toHex())},
            {"baseNcrh", QString::fromLatin1(ncrh.bytes.toHex())},
            {"generation", double(generation)},
            {"directEnabled", direct},
            {"endpoints", endpoints}};
}
} // namespace dmash::broker

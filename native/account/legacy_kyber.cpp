#include "legacy_kyber.h"
#include <mutex>
#include <openssl/crypto.h>
extern "C" void wasm_rt_init(void);
extern "C" int dmash_legacy_kyber_execute(int, const uint8_t *, const uint8_t *, uint8_t *,
                                          uint8_t *);
namespace dmash::account {
namespace {
std::mutex runtimeMutex;
std::once_flag initialized;
const uint8_t *input(const QByteArray &b) {
    return reinterpret_cast<const uint8_t *>(b.constData());
}
uint8_t *output(QByteArray &b) { return reinterpret_cast<uint8_t *>(b.data()); }
void need(bool b, const char *code) {
    if (!b)
        throw AccountError(code);
}
int execute(int op, const QByteArray &a, const QByteArray &b, QByteArray &c, QByteArray &d) {
    std::lock_guard<std::mutex> lock(runtimeMutex);
    std::call_once(initialized, [] { wasm_rt_init(); });
    return dmash_legacy_kyber_execute(op, input(a), input(b), output(c), output(d));
}
} // namespace
SecretBytes::SecretBytes(QByteArray bytes) : bytes_(std::move(bytes)) { bytes_.detach(); }
SecretBytes::~SecretBytes() { clear(); }
SecretBytes::SecretBytes(SecretBytes &&other) noexcept : bytes_(std::move(other.bytes_)) {}
SecretBytes &SecretBytes::operator=(SecretBytes &&other) noexcept {
    if (this != &other) {
        clear();
        bytes_ = std::move(other.bytes_);
    }
    return *this;
}
const QByteArray &SecretBytes::bytes() const { return bytes_; }
void SecretBytes::clear() {
    OPENSSL_cleanse(bytes_.data(), bytes_.size());
    bytes_.clear();
}
KyberKeyPair LegacyKyber::generateKeys() {
    QByteArray pk(1184, Qt::Uninitialized), sk(2400, Qt::Uninitialized);
    if (execute(0, {}, {}, pk, sk) != 0) {
        OPENSSL_cleanse(sk.data(), sk.size());
        throw AccountError("LEGACY_KYBER_FAILED");
    }
    return {std::move(pk), SecretBytes(std::move(sk))};
}
KyberEncapsulation LegacyKyber::encapsulate(const QByteArray &pk) {
    need(pk.size() == 1184, "LEGACY_KYBER_KEY_SIZE");
    QByteArray ct(1088, Qt::Uninitialized), ss(32, Qt::Uninitialized);
    if (execute(1, pk, {}, ct, ss) != 0) {
        OPENSSL_cleanse(ss.data(), ss.size());
        throw AccountError("LEGACY_KYBER_FAILED");
    }
    return {std::move(ct), SecretBytes(std::move(ss))};
}
SecretBytes LegacyKyber::decapsulate(const QByteArray &ct, const QByteArray &sk) {
    need(ct.size() == 1088 && sk.size() == 2400, "LEGACY_KYBER_KEY_SIZE");
    QByteArray ss(32, Qt::Uninitialized), unused;
    if (execute(2, ct, sk, ss, unused) != 0) {
        OPENSSL_cleanse(ss.data(), ss.size());
        throw AccountError("LEGACY_KYBER_FAILED");
    }
    return SecretBytes(std::move(ss));
}
} // namespace dmash::account

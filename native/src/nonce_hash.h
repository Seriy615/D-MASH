#pragma once
#include <QByteArray>
#include <QtGlobal>
#include <openssl/evp.h>
#include <atomic>
#include <optional>
namespace dmash {
// Trusted local acceleration only: the JS protocol still builds/validates the
// complete activation transcript and verifies the returned proof unchanged.
class NonceHash final {
    EVP_MD_CTX* prefix_ = nullptr;
    EVP_MD_CTX* work_ = nullptr;
public:
    explicit NonceHash(const QByteArray& prefix);
    ~NonceHash();
    NonceHash(const NonceHash&) = delete;
    QByteArray digest(quint64 nonce);
    struct Match { quint64 nonce; QByteArray digest; };
    std::optional<Match> search(quint64 start, int count, int difficulty, const std::atomic_bool* cancelled = nullptr);
};
}

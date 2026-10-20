#pragma once
#include <QByteArray>
#include <stdexcept>
namespace dmash::account {
class AccountError final : public std::runtime_error {
  public:
    explicit AccountError(const char *code) : std::runtime_error(code) {}
};
// Account process only. Caller copies/provider temporaries require their own cleanup.
class SecretBytes final {
  public:
    explicit SecretBytes(QByteArray value);
    ~SecretBytes();
    SecretBytes(SecretBytes &&) noexcept;
    SecretBytes &operator=(SecretBytes &&) noexcept;
    SecretBytes(const SecretBytes &) = delete;
    SecretBytes &operator=(const SecretBytes &) = delete;
    const QByteArray &bytes() const;
    void clear();

  private:
    QByteArray bytes_;
};
struct KyberKeyPair {
    QByteArray publicKey;
    SecretBytes secretKey;
};
struct KyberEncapsulation {
    QByteArray ciphertext;
    SecretBytes secret;
};
// Executes the EXACT existing kyber768.wasm translated with WABT wasm2c.
// This is legacy Kyber compatibility, not a replacement ML-KEM implementation.
// No import/Root API exists and this library must never enter the network daemon.
class LegacyKyber final {
  public:
    static KyberKeyPair generateKeys();
    static KyberEncapsulation encapsulate(const QByteArray &existingPublicKey);
    static SecretBytes decapsulate(const QByteArray &capsule, const QByteArray &existingSecretKey);
};
} // namespace dmash::account

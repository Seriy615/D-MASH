#pragma once
#include <QByteArray>
namespace dmash {
// Transport crypto primitives. WebCrypto algorithm/usage checks belong to its
// allowlisted JS adapter; these methods do not access the credential broker.
class CryptoPort final {
  public:
    static QByteArray random(int bytes);
    static bool ed25519Verify(const QByteArray& message, const QByteArray& signature, const QByteArray& publicKey);
    static QByteArray x25519(const QByteArray& scalar, const QByteArray& publicKey);
    static QByteArray sha256(const QByteArray&);
    static QByteArray hmacSha256(const QByteArray& key, const QByteArray& data);
    static QByteArray hkdfSha256(const QByteArray& key, const QByteArray& salt,
                                 const QByteArray& info, int bytes);
    static QByteArray aesGcm(bool encrypt, const QByteArray& key, const QByteArray& iv,
                             const QByteArray& aad, const QByteArray& data, int tagBits = 128);
};
} // namespace dmash

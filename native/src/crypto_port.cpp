#include "crypto_port.h"
#include <memory>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdexcept>
namespace dmash {
namespace {
constexpr int MaxBuffer = 2 * 1024 * 1024;
void require(bool ok) {
    if (!ok)
        throw std::runtime_error("Native transport crypto operation rejected");
}
void bounded(const QByteArray& data) { require(data.size() <= MaxBuffer); }
struct WipeOnFailure {
    QByteArray& bytes;
    bool committed = false;
    ~WipeOnFailure() {
        if (!committed)
            OPENSSL_cleanse(bytes.data(), size_t(bytes.size()));
    }
};
} // namespace
QByteArray CryptoPort::random(int n) {
    require(n >= 0 && n <= 65536);
    QByteArray out(n, Qt::Uninitialized);
    WipeOnFailure wipe{out};
    require(n == 0 || RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), n) == 1);
    wipe.committed = true;
    return out;
}
bool CryptoPort::ed25519Verify(const QByteArray& message, const QByteArray& signature, const QByteArray& publicKey) {
    bounded(message);require(signature.size()==64 && publicKey.size()==32);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(EVP_PKEY_new_raw_public_key_ex(nullptr,"ED25519",nullptr,reinterpret_cast<const unsigned char*>(publicKey.constData()),32),EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    require(key && context && EVP_DigestVerifyInit(context.get(),nullptr,nullptr,nullptr,key.get())==1);
    return EVP_DigestVerify(context.get(),reinterpret_cast<const unsigned char*>(signature.constData()),64,reinterpret_cast<const unsigned char*>(message.constData()),size_t(message.size()))==1;
}
QByteArray CryptoPort::x25519(const QByteArray& scalar, const QByteArray& publicKey) {
    require(scalar.size()==32 && publicKey.size()==32);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(EVP_PKEY_new_raw_private_key_ex(nullptr,"X25519",nullptr,reinterpret_cast<const unsigned char*>(scalar.constData()),32),EVP_PKEY_free);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> peer(EVP_PKEY_new_raw_public_key_ex(nullptr,"X25519",nullptr,reinterpret_cast<const unsigned char*>(publicKey.constData()),32),EVP_PKEY_free);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(key ? EVP_PKEY_CTX_new_from_pkey(nullptr,key.get(),nullptr) : nullptr,EVP_PKEY_CTX_free);
    require(key && peer && context && EVP_PKEY_derive_init(context.get())==1 && EVP_PKEY_derive_set_peer(context.get(),peer.get())==1);
    QByteArray result(32,0);size_t length=32;
    // TweetNaCl scalarMult returns zero for low-order input. Existing protocol
    // encoding guards reject it; preserve that return contract at this port.
    if(EVP_PKEY_derive(context.get(),reinterpret_cast<unsigned char*>(result.data()),&length)!=1)result.fill(0);
    else require(length==32);
    return result;
}
QByteArray CryptoPort::sha256(const QByteArray& data) {
    bounded(data);
    QByteArray out(32, Qt::Uninitialized);
    WipeOnFailure wipe{out};
    size_t n = 0;
    require(EVP_Q_digest(nullptr, "SHA256", nullptr, data.constData(), size_t(data.size()),
                         reinterpret_cast<unsigned char*>(out.data()), &n) == 1 &&
            n == 32);
    wipe.committed = true;
    return out;
}
QByteArray CryptoPort::hmacSha256(const QByteArray& key, const QByteArray& data) {
    bounded(key);
    bounded(data);
    QByteArray out(32, Qt::Uninitialized);
    WipeOnFailure wipe{out};
    size_t n = 0;
    require(EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key.constData(),
                      size_t(key.size()), reinterpret_cast<const unsigned char*>(data.constData()),
                      size_t(data.size()), reinterpret_cast<unsigned char*>(out.data()), 32, &n) &&
            n == 32);
    wipe.committed = true;
    return out;
}
QByteArray CryptoPort::hkdfSha256(const QByteArray& key, const QByteArray& salt,
                                  const QByteArray& info, int n) {
    bounded(key);
    bounded(salt);
    bounded(info);
    require(n > 0 && n <= 255 * 32);
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr),
                                                          EVP_KDF_free);
    require(bool(kdf));
    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> ctx(EVP_KDF_CTX_new(kdf.get()),
                                                                  EVP_KDF_CTX_free);
    require(bool(ctx));
    char digest[] = "SHA256";
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<char*>(key.constData()),
                                          size_t(key.size())),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<char*>(salt.constData()),
                                          size_t(salt.size())),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<char*>(info.constData()),
                                          size_t(info.size())),
        OSSL_PARAM_END};
    QByteArray out(n, Qt::Uninitialized);
    WipeOnFailure wipe{out};
    require(EVP_KDF_derive(ctx.get(), reinterpret_cast<unsigned char*>(out.data()), size_t(n), p) ==
            1);
    wipe.committed = true;
    return out;
}
QByteArray CryptoPort::aesGcm(bool encrypt, const QByteArray& key, const QByteArray& iv,
                              const QByteArray& aad, const QByteArray& data, int tagBits) {
    bounded(data);
    bounded(aad);
    require(key.size() == 16 || key.size() == 24 || key.size() == 32);
    require(!iv.isEmpty() && iv.size() <= 256);
    require(tagBits == 32 || tagBits == 64 || tagBits == 96 || tagBits == 104 || tagBits == 112 ||
            tagBits == 120 || tagBits == 128);
    const int tag = tagBits / 8;
    require(encrypt || data.size() >= tag);
    const auto name = QByteArray("AES-") + QByteArray::number(key.size() * 8) + "-GCM";
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(
        EVP_CIPHER_fetch(nullptr, name.constData(), nullptr), EVP_CIPHER_free);
    require(bool(cipher));
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(),
                                                                        EVP_CIPHER_CTX_free);
    require(bool(ctx));
    require(EVP_CipherInit_ex(ctx.get(), cipher.get(), nullptr, nullptr, nullptr,
                              encrypt ? 1 : 0) == 1);
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, int(iv.size()), nullptr) == 1);
    require(EVP_CipherInit_ex(ctx.get(), nullptr, nullptr,
                              reinterpret_cast<const unsigned char*>(key.constData()),
                              reinterpret_cast<const unsigned char*>(iv.constData()),
                              encrypt ? 1 : 0) == 1);
    int n = 0;
    require(EVP_CipherUpdate(ctx.get(), nullptr, &n,
                             reinterpret_cast<const unsigned char*>(aad.constData()),
                             int(aad.size())) == 1);
    const int input = int(data.size()) - (encrypt ? 0 : tag);
    QByteArray out(input + 16, Qt::Uninitialized);
    WipeOnFailure wipe{out};
    int used = 0;
    require(EVP_CipherUpdate(ctx.get(), reinterpret_cast<unsigned char*>(out.data()), &used,
                             reinterpret_cast<const unsigned char*>(data.constData()), input) == 1);
    if (!encrypt)
        require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag,
                                    const_cast<char*>(data.constData() + input)) == 1);
    if (EVP_CipherFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(out.data()) + used, &n) !=
        1) {
        throw std::runtime_error("Native transport authentication failed");
    }
    used += n;
    if (encrypt) {
        require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag, out.data() + used) == 1);
        used += tag;
    }
    out.resize(used);
    wipe.committed = true;
    return out;
}
} // namespace dmash

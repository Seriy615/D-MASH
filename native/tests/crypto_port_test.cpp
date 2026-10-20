#include "crypto_port.h"
#include <QCoreApplication>
#include <iostream>
#include <stdexcept>
using dmash::CryptoPort;
static void require(bool ok) {
    if (!ok)
        throw std::runtime_error("crypto assertion failed");
}
template <class F> static void rejects(F f) {
    bool bad = false;
    try {
        f();
    } catch (const std::exception&) {
        bad = true;
    }
    require(bad);
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        const auto publicKey=QByteArray::fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        auto signature=QByteArray::fromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        require(CryptoPort::ed25519Verify({},signature,publicKey));
        require(!CryptoPort::ed25519Verify("changed",signature,publicKey));signature[0]^=1;require(!CryptoPort::ed25519Verify({},signature,publicKey));
        rejects([&]{CryptoPort::ed25519Verify({},QByteArray(63,0),publicKey);});
        const auto scalar=QByteArray::fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        const auto peer=QByteArray::fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        require(CryptoPort::x25519(scalar,peer).toHex()=="4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        require(CryptoPort::x25519(scalar,QByteArray(32,0))==QByteArray(32,0));
        require(CryptoPort::sha256("abc").toHex() ==
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        require(CryptoPort::hmacSha256(QByteArray(20, '\x0b'), "Hi There").toHex() ==
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        require(
            CryptoPort::hkdfSha256(QByteArray(22, '\x0b'),
                                   QByteArray::fromHex("000102030405060708090a0b0c"),
                                   QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9"), 42)
                .toHex() ==
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
        const QByteArray key(16, 0), iv(12, 0), plain(16, 0);
        const auto sealed = CryptoPort::aesGcm(true, key, iv, {}, plain);
        require(sealed.toHex() ==
                "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
        require(CryptoPort::aesGcm(false, key, iv, {}, sealed) == plain);
        const QByteArray key256(32, 0);
        const auto sealed256 = CryptoPort::aesGcm(true, key256, iv, {}, plain);
        require(sealed256.toHex() ==
                "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
        require(CryptoPort::aesGcm(false, key256, iv, {}, sealed256) == plain);
        auto bad256 = sealed256;
        bad256[bad256.size() - 1] = char(bad256.back() ^ 1);
        rejects([&] { CryptoPort::aesGcm(false, key256, iv, {}, bad256); });
        require(CryptoPort::aesGcm(true, key, iv, {}, {}).toHex() ==
                "58e2fccefa7e3061367f1d57a4e7455a");
        const auto withAad = CryptoPort::aesGcm(true, key, iv, "bound context", plain);
        require(CryptoPort::aesGcm(false, key, iv, "bound context", withAad) == plain);
        rejects([&] { CryptoPort::aesGcm(false, key, iv, "wrong context", withAad); });
        auto wrongKey = key;
        wrongKey[0] = 1;
        rejects([&] { CryptoPort::aesGcm(false, wrongKey, iv, "bound context", withAad); });
        auto damaged = withAad;
        damaged[0] = char(damaged[0] ^ 1);
        rejects([&] { CryptoPort::aesGcm(false, key, iv, "bound context", damaged); });
        rejects([&] { CryptoPort::aesGcm(false, key, iv, "bound context", withAad.chopped(1)); });
        for (int tag : {32, 64, 96, 104, 112, 120, 128}) {
            const auto blob = CryptoPort::aesGcm(true, key, iv, {}, plain, tag);
            require(blob.size() == 16 + tag / 8);
            require(CryptoPort::aesGcm(false, key, iv, {}, blob, tag) == plain);
        }
        rejects([&] { CryptoPort::aesGcm(true, key, iv, {}, plain, 48); });
        rejects([&] { CryptoPort::aesGcm(true, QByteArray(15, 0), iv, {}, plain); });
        rejects([&] { CryptoPort::sha256(QByteArray(2 * 1024 * 1024 + 1, 0)); });
        rejects([] { CryptoPort::random(65537); });
        rejects([&] { CryptoPort::hkdfSha256(key, {}, {}, 8161); });
        require(CryptoPort::random(0).isEmpty());
        require(CryptoPort::random(32) != CryptoPort::random(32));
        std::cout << "PASS transport SHA256/HMAC/HKDF/NIST-GCM vectors, authentication rejection "
                     "and bounds\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}

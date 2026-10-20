#include "legacy_kyber.h"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <future>
#include <iostream>
using namespace dmash::account;
void check(bool b) {
    if (!b)
        throw std::runtime_error("KEM assertion failed");
}
QString b64(const QByteArray &b) { return QString::fromLatin1(b.toBase64()); }
QByteArray decode(const QJsonValue &v, int size) {
    auto b =
        QByteArray::fromBase64(v.toString().toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
    check(b.size() == size && b.toBase64() == v.toString().toLatin1());
    return b;
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    try {
        if (argc == 2 && QString(argv[1]) == "--fixture") {
            auto keys = LegacyKyber::generateKeys();
            auto capsule = LegacyKyber::encapsulate(keys.publicKey);
            QJsonObject o{{"pk", b64(keys.publicKey)},
                          {"sk", b64(keys.secretKey.bytes())},
                          {"ct", b64(capsule.ciphertext)},
                          {"ss", b64(capsule.secret.bytes())}};
            std::cout << QJsonDocument(o).toJson(QJsonDocument::Compact).constData();
            return 0;
        }
        if (argc == 2 && QString(argv[1]) == "--decap") {
            std::string line;
            std::getline(std::cin, line);
            check(line.size() <= 16384);
            auto o = QJsonDocument::fromJson(QByteArray::fromStdString(line)).object();
            SecretBytes sk(decode(o.value("sk"), 2400));
            auto secret = LegacyKyber::decapsulate(decode(o.value("ct"), 1088), sk.bytes());
            std::cout << secret.bytes().toBase64().constData();
            return 0;
        }
        auto keys = LegacyKyber::generateKeys();
        check(keys.publicKey.size() == 1184 && keys.secretKey.bytes().size() == 2400);
        auto capsule = LegacyKyber::encapsulate(keys.publicKey);
        auto secret = LegacyKyber::decapsulate(capsule.ciphertext, keys.secretKey.bytes());
        check(secret.bytes() == capsule.secret.bytes());
        auto corrupted = capsule.ciphertext;
        corrupted[0] = char(corrupted[0] ^ 1);
        auto rejected = LegacyKyber::decapsulate(corrupted, keys.secretKey.bytes());
        check(rejected.bytes() != secret.bytes());
        bool failed = false;
        try {
            LegacyKyber::encapsulate(QByteArray(1183, 'x'));
        } catch (const AccountError &) {
            failed = true;
        }
        check(failed);
        auto other = std::async(std::launch::async, [] { return LegacyKyber::generateKeys(); });
        auto second = LegacyKyber::generateKeys();
        check(second.publicKey != keys.publicKey && other.get().publicKey != keys.publicKey);
        secret.clear();
        check(secret.bytes().isEmpty());
        std::cout << "PASS exact translated legacy Kyber native roundtrip, implicit rejection, "
                     "length refusal, concurrent owners and disposal\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "FAIL " << e.what() << "\n";
        return 1;
    }
}

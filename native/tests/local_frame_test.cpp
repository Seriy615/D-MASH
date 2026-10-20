#include "local_ipc.h"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QtEndian>
#include <cassert>
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    auto rejects = [](const QByteArray& bytes, qsizetype cap) {
        try {
            dmash::parseLocalObject(bytes, cap);
            return false;
        } catch (...) {
            return true;
        }
    };
    assert(rejects(QByteArray(), 65536));
    assert(rejects("[]", 65536));
    assert(rejects("{}", 1));
    assert(rejects(QByteArray("{\"x\":\"\xff\"}"), 65536));
    assert(rejects(QByteArray("{\"x\":\"\xc3\"}"), 65536));
    assert(rejects(QByteArray("{\"x\":\"\xed\xa0\x80\"}"), 65536));
    const QJsonObject object{{"v", 1}, {"value", QString::fromUtf8("\xe2\x82\xac")}};
    auto frame = dmash::localFrame(object);
    const auto length = qFromBigEndian<quint32>(frame.constData());
    assert(length == frame.size() - 4);
    assert(dmash::parseLocalObject(frame.mid(4), 524288) == object);
    bool rejected = false;
    try {
        dmash::localFrame(object, 1);
    } catch (...) {
        rejected = true;
    }
    assert(rejected);
}

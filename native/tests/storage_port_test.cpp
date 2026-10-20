#include "storage_port.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <future>
#include <iostream>
#include <stdexcept>
using dmash::RelationshipSqlStore;
static void require(bool value) {
    if (!value)
        throw std::runtime_error("storage assertion failed");
}
template <class F> static void rejects(F f) {
    bool rejected = false;
    try {
        f();
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected);
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        QTemporaryDir dir;
        require(dir.isValid());
        const auto file = dir.filePath("encrypted.sqlite");
        const QByteArray iv(12, 'i'), cipher(32, 'c');
        const QString peer(64, 'a'), other(64, 'b');
        {
            RelationshipSqlStore one(file), two(file);
            require(!one.read("binding"));
            require(one.cas("binding", std::nullopt, iv, cipher, true, 1));
            require(!two.cas("binding", std::nullopt, iv, cipher, true, 1));
            require(one.cas(peer, std::nullopt, iv, cipher, false, 1));
            const auto row = two.read(peer);
            require(row && row->revision == 1 && row->ciphertext == cipher && row->iv == iv);
            require(two.cas(peer, 1, iv, QByteArray(32, 'd'), false, 1));
            require(!one.cas(peer, 1, iv, cipher, false, 1));
            require(one.read(peer)->revision == 2);
            rejects([&] { one.cas(other, std::nullopt, iv, cipher, false, 1); });
            require(!one.read(other));
            require(one.cas(peer, 2, iv, cipher, false, 1));
            rejects([&] { one.cas(peer, 3, QByteArray(11, 'x'), cipher, false, 1); });
            require(one.read(peer)->revision == 3);
            require(std::async(std::launch::async, [&] {
                        try {
                            one.read(peer);
                            return false;
                        } catch (const std::exception&) {
                            return true;
                        }
                    }).get());
            one.close();
            rejects([&] { one.read(peer); });
        }
        {
            RelationshipSqlStore restored(file);
            require(restored.read(peer)->revision == 3);
            require(restored.read(peer)->ciphertext == cipher);
        }
        {
            RelationshipSqlStore orphan(dir.filePath("orphan.sqlite"));
            require(orphan.cas(peer, std::nullopt, iv, cipher, false, 1));
            rejects([&] { orphan.cas("binding", std::nullopt, iv, cipher, true, 1); });
            require(!orphan.read("binding"));
            require(orphan.read(peer)->revision == 1);
        }
        std::cout
            << "PASS native SQL atomic revision/binding/orphan/quota/reopen/thread ownership\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}

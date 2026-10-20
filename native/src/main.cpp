#include "js_actor.h"
#include "local_ipc.h"
#include <limits>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalSocket>
#include <QRegularExpression>
#include <QTimer>
#include <QtEndian>
#include <csignal>
#include <openssl/crypto.h>
#ifdef Q_OS_UNIX
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <iostream>
namespace {
struct WipeInput {
    QByteArray& bytes;
    ~WipeInput() {
        if (!bytes.isEmpty())
            OPENSSL_cleanse(bytes.data(), size_t(bytes.size()));
    }
};
volatile std::sig_atomic_t stopping = 0;
void signalStop(int) { stopping = 1; }
} // namespace
int dmashRunNodeHost(QCoreApplication& app, int argc, char** argv) {
    QStringList arguments;
    for (int i = 0; i < argc; ++i)
        arguments.append(QString::fromLocal8Bit(argv[i]));
    app.setApplicationName("D-MASH Node host");
    QCommandLineParser cli;
    cli.addHelpOption();
    cli.addOption({"profile", "Private Node profile directory", "directory"});
    cli.addOption(
        {"bundle", "Scoped credential broker input (max64KiB; no Root/Account material)", "file"});
    cli.addOption({"bootstrap-fd", "Inherited broker service socket descriptor", "descriptor"});
    cli.addOption({"bootstrap-handle", "Inherited Windows broker named-pipe handle", "handle"});
    cli.addOption({"service-query", "Send existing authenticated SERVICE_QUERY after connection"});
    cli.addOption(
        {"run-for", "Stop cleanly after bounded seconds (0 keeps running)", "seconds", "0"});
    cli.process(arguments);
    try {
        if (!cli.isSet("profile") || int(cli.isSet("bundle")) + int(cli.isSet("bootstrap-fd")) + int(cli.isSet("bootstrap-handle")) != 1)
            throw std::runtime_error("arguments");
        dmash::TransportBundle bundle;
        dmash::BootstrapInstall install;
        std::unique_ptr<QLocalSocket> bootstrap;
        const bool service = cli.isSet("bootstrap-fd") || cli.isSet("bootstrap-handle");
        if (service) {
            bool valid = false;
            qintptr fd = -1;
#ifdef Q_OS_WIN
            const auto value = cli.value("bootstrap-handle").toULongLong(&valid);
            if (!cli.isSet("bootstrap-handle") || value > std::numeric_limits<quintptr>::max())
                valid = false;
            fd = qintptr(quintptr(value));
#else
            if (cli.isSet("bootstrap-fd")) fd = cli.value("bootstrap-fd").toInt(&valid);
#endif
            if (!valid || fd == -1 || fd == 0)
                throw std::runtime_error("bootstrap descriptor");
            install = dmash::readBootstrapInstall(fd);
            bundle = std::move(install.bundle);
            bootstrap = std::make_unique<QLocalSocket>();
            if (!bootstrap->setSocketDescriptor(fd, QLocalSocket::ConnectedState,
                                                QIODevice::ReadWrite))
                throw std::runtime_error("bootstrap descriptor");
            bootstrap->setReadBufferSize(65540);
        } else {
            const QFileInfo info(cli.value("bundle"));
            QFile file;
#ifdef Q_OS_UNIX
            // Bind regular-file/owner/mode checks to the opened descriptor. The
            // surrounding private directory still belongs to the same-UID boundary.
            const auto path = QFile::encodeName(info.absoluteFilePath());
            const int fd = ::open(path.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (fd < 0)
                throw std::runtime_error("bundle open");
            struct stat status {};
            if (::fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
                status.st_uid != geteuid() || (status.st_mode & 0077) || status.st_size < 0 ||
                status.st_size > 65536) {
                ::close(fd);
                throw std::runtime_error("private input required");
            }
            if (!file.open(fd, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) {
                ::close(fd);
                throw std::runtime_error("bundle open");
            }
#else
            if (info.isSymLink() || !info.isFile() || info.size() > 65536)
                throw std::runtime_error("bundle file");
            file.setFileName(info.absoluteFilePath());
            if (!file.open(QIODevice::ReadOnly))
                throw std::runtime_error("bundle open");
#endif
            auto raw = file.read(65537);
            WipeInput wipe{raw};
            if (raw.size() > 65536)
                throw std::runtime_error("bundle limit");
            QJsonParseError parse;
            auto doc = QJsonDocument::fromJson(raw, &parse);
            if (parse.error != QJsonParseError::NoError || !doc.isObject())
                throw std::runtime_error("bundle JSON");
            bundle = dmash::TransportBundle::parse(doc.object());
            raw.fill(0);
            raw.clear();
            doc = QJsonDocument();
        }
        const int endpoints = bundle.endpoints.size();
        bool ok = false;
        const int seconds = cli.value("run-for").toInt(&ok);
        if (!ok || seconds < 0 || seconds > 900)
            throw std::runtime_error("deadline");
        dmash::JsActor actor(cli.value("profile"));
        bool failed = false;
        std::unique_ptr<dmash::LocalIpc> ipc;
        bool ready = false, revoked = false;
        QByteArray bootstrapInput;
        quint32 bootstrapLength = 0;
        QElapsedTimer bootstrapRate;
        bootstrapRate.start();
        int bootstrapCount = 0;
        auto sendBootstrap = [&](const QJsonObject& value) {
            if (!bootstrap)
                return;
            const auto frame = dmash::localFrame(value, 65536);
            if (bootstrap->bytesToWrite() + frame.size() > 65536 ||
                bootstrap->write(frame) != frame.size())
                throw std::runtime_error("bootstrap output");
            bootstrap->flush();
        };
        actor.onBootstrapFloors = [&](const QJsonObject& floors) {
            if (!bootstrap)
                return;
            auto response = floors;
            response.insert("v", 1);
            response.insert("type", "STALE_FLOOR");
            response.insert("request_id", install.requestId);
            try {
                sendBootstrap(response);
            } catch (...) {
            };
        };
        if (bootstrap) {
            auto lostBroker = [&] {
                if (ready && !revoked) {
                    try {
                        actor.revokeTransport();
                    } catch (...) {
                        failed = true;
                    }
                }
                actor.close();
                if (ipc)
                    ipc->close();
                app.quit();
            };
            QObject::connect(bootstrap.get(), &QLocalSocket::disconnected, &app, lostBroker);
            // The inherited broker-only channel renews its configured principals;
            // policy/revoke stay on the existing role-scoped local dispatch.
            QObject::connect(bootstrap.get(), &QLocalSocket::readyRead, &app, [&, lostBroker] {
                try {
                    if (!ready || !ipc)
                        throw std::runtime_error("bootstrap not ready");
                    while (bootstrap->bytesAvailable()) {
                        if (bootstrapRate.elapsed() >= 1000) {
                            bootstrapRate.restart();
                            bootstrapCount = 0;
                        }
                        const qsizetype target = bootstrapLength ? qsizetype(bootstrapLength) : 4;
                        bootstrapInput += bootstrap->read(target - bootstrapInput.size());
                        if (bootstrapInput.size() < target)
                            return;
                        if (!bootstrapLength) {
                            bootstrapLength = qFromBigEndian<quint32>(bootstrapInput.constData());
                            bootstrapInput.clear();
                            if (!bootstrapLength || bootstrapLength > 65536)
                                throw std::runtime_error("bootstrap frame limit");
                            continue;
                        }
                        if (++bootstrapCount > 16)
                            throw std::runtime_error("bootstrap rate limit");
                        auto raw = std::move(bootstrapInput);
                        WipeInput wipe{raw};
                        bootstrapInput.clear();
                        bootstrapLength = 0;
                        const auto command = dmash::parseLocalObject(raw, 65536);
                        auto keys = command.keys();
                        keys.sort();
                        QStringList wanted{"v", "type", "request_id", "principal", "ttl_seconds"};
                        wanted.sort();
                        const auto ttl = command.value("ttl_seconds").toDouble(-1);
                        if (keys != wanted || command.value("v") != 1 ||
                            (command.value("type") != "MintCapability" &&
                             command.value("type") != "RenewCapabilityLease") ||
                            !QRegularExpression("^[A-Za-z0-9_.-]{1,64}$")
                                 .match(command.value("request_id").toString())
                                 .hasMatch() ||
                            !command.value("principal").isString() ||
                            !command.value("ttl_seconds").isDouble() || ttl < 1 || ttl > 86400 ||
                            ttl != qint64(ttl))
                            throw std::runtime_error("bootstrap control rejected");
                        const bool extend = command.value("type") == "RenewCapabilityLease";
                        auto response = extend
                            ? ipc->extendCapabilityLease(command.value("principal").toString(), qint64(ttl))
                            : ipc->renewCapability(command.value("principal").toString(), qint64(ttl));
                        response.insert("v", 1);
                        response.insert("type", extend ? "CapabilityLeaseRenewed" : "CapabilityMinted");
                        response.insert("request_id", command.value("request_id"));
                        sendBootstrap(response);
                    }
                } catch (...) {
                    lostBroker();
                }
            });
        }
        actor.onEvent = [&](const QJsonObject& event) {
            std::cout << QJsonDocument(event).toJson(QJsonDocument::Compact).constData()
                      << std::endl;
            const auto type = event.value("event").toString();
            if (type == "ready") {
                ready = true;
                if (service) {
                    try {
                        ipc = std::make_unique<dmash::LocalIpc>(
                            actor, cli.value("profile"), event.value("ownerGeneration").toInteger(),
                            install.principals);
                        auto response = ipc->bootstrapReply();
                        response.insert("request_id", install.requestId);
                        sendBootstrap(response);
                    } catch (...) {
                        failed = true;
                        actor.close();
                        QTimer::singleShot(0, &app, &QCoreApplication::quit);
                        return;
                    }
                }
                for (int i = 0; i < endpoints; i++)
                    actor.connectPeer(i);
            }
            if (type == "connected" && cli.isSet("service-query"))
                actor.queryService(event.value("index").toInt());
            if (type == "transport-revoked") {
                revoked = true;
                actor.close();
                QTimer::singleShot(100, &app, &QCoreApplication::quit);
            }
            if (type == "error") {
                failed = true;
                QTimer::singleShot(0, &app, &QCoreApplication::quit);
            }
        };
        QObject::connect(&app, &QCoreApplication::aboutToQuit, &actor, [&] { actor.close(); });
        std::signal(SIGINT, signalStop);
        std::signal(SIGTERM, signalStop);
        QTimer signalPoll;
        signalPoll.setInterval(100);
        QObject::connect(&signalPoll, &QTimer::timeout, &app, [&] {
            if (stopping)
                app.quit();
        });
        signalPoll.start();
        if (seconds)
            QTimer::singleShot(seconds * 1000, &app, &QCoreApplication::quit);
        actor.initialize(std::move(bundle), service ? install.policyRevision : 1);
        const int result = app.exec();
        if (ipc)
            ipc->close();
        actor.close();
        return failed ? 1 : result;
    } catch (...) {
        std::cerr << "HOST_START_FAILED\n";
        return 1;
    }
}

#ifndef DMASH_HOST_EXTERNAL_APP
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    return dmashRunNodeHost(app, argc, argv);
}
#endif

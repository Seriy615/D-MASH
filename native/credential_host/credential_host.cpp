#include "credential_host.h"
#include "account_service.h"
#include "daemon_rpc.h"
#include "node_miner.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QLockFile>
#include <QPointer>
#include <QSaveFile>
#include <QTimer>
#include <QtEndian>
#include <future>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#ifdef Q_OS_UNIX
#include <sys/socket.h>
#include <unistd.h>
#endif
#ifdef Q_OS_WIN
#include "os_windows.h"
#endif
namespace dmash::credential {
namespace {
void need(bool b, const char* code) {
    if (!b)
        throw account::AccountError(code);
}
const auto ownerOnly = QFileDevice::ReadOwner | QFileDevice::WriteOwner;
void privateDirectory(const QString& path) {
    need(!QFileInfo(path).isSymLink(), "PROFILE_PATH_REJECTED");
#ifdef Q_OS_WIN
    windowsLocal::ensurePrivateProfile(path.toStdWString());
#else
    if (!QDir(path).exists())
        need(QDir().mkpath(path) && QFile::setPermissions(path, ownerOnly | QFileDevice::ExeOwner),
             "PROFILE_DIRECTORY_UNAVAILABLE");
    auto info = QFileInfo(path);
    need(info.isDir() && info.ownerId() == geteuid() &&
             !(info.permissions() &
               (QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup |
                QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther)),
         "PROFILE_PATH_REJECTED");
#endif
}
QByteArray openKey(const QString& profile) {
    const auto name = QDir(profile).filePath("app-local.key");
    if (!QFileInfo::exists(name)) {
        for (auto file : {"credentials.sqlite", "account.sqlite", "control.sqlite"})
            need(!QFileInfo::exists(QDir(profile).filePath(file)), "PROFILE_KEY_RECOVERY_REQUIRED");
        QByteArray random(32, Qt::Uninitialized);
        need(RAND_bytes(reinterpret_cast<unsigned char*>(random.data()), 32) == 1,
             "PROFILE_KEY_UNAVAILABLE");
        QFile key(name);
        need(key.open(QIODevice::WriteOnly | QIODevice::NewOnly), "PROFILE_KEY_UNAVAILABLE");
        need(key.setPermissions(ownerOnly) && key.write(random) == 32 && key.flush(),
             "PROFILE_KEY_UNAVAILABLE");
#ifdef Q_OS_UNIX
        need(::fsync(key.handle()) == 0, "PROFILE_KEY_UNAVAILABLE");
#endif
        OPENSSL_cleanse(random.data(), size_t(random.size()));
    }
    QFileInfo info(name);
    need(info.isFile() && !info.isSymLink(), "PROFILE_KEY_RECOVERY_REQUIRED");
#ifdef Q_OS_WIN
    windowsLocal::requirePrivateFile(name.toStdWString(), false);
#else
    need(info.ownerId() == geteuid() &&
             !(info.permissions() & (QFileDevice::ReadGroup | QFileDevice::WriteGroup |
                                     QFileDevice::ReadOther | QFileDevice::WriteOther)),
         "PROFILE_KEY_RECOVERY_REQUIRED");
#endif
    QFile f(name);
    need(f.open(QIODevice::ReadOnly) && f.size() == 32, "PROFILE_KEY_RECOVERY_REQUIRED");
    return f.readAll();
}
account::AccountResult failure(const QString& code) {
    account::AccountResult r;
    r.code = code;
    return r;
}
struct JobResult {
    account::AccountResult result;
    broker::BrokerResult transport;
    bool startNode = false;
    bool unlocked = false;
};
} // namespace
struct CredentialHost::State {
    QString profile, accountPath, endpoint;
    QLockFile lock;
    QLocalServer server;
    QTimer poll;
    std::shared_ptr<NodeSupervisor> supervisor;
    std::shared_ptr<DaemonRpc> daemon = std::make_shared<DaemonRpc>();
    std::unique_ptr<broker::BrokerService> broker;
    std::unique_ptr<account::AccountService> account;
    std::future<JobResult> pending;
    QPointer<QLocalSocket> pendingSocket;
    QString pendingId, pendingMethod, phase;
    QJsonObject policy, pendingPolicy;
    quint64 jobEpoch = 1, pendingEpoch = 0;
    bool rootLocked = true;
    QJsonObject activeAccount;
    struct Client {
        QByteArray input;
        quint32 length = 0;
    };
    std::map<QLocalSocket*, Client> clients;
    State(QString directory, std::shared_ptr<NodeSupervisor> node)
        : profile(QDir(directory).absolutePath()),
          accountPath(QDir(profile).filePath("account.sqlite")),
          lock(QDir(profile).filePath("credential-host.lock")), supervisor(std::move(node)) {
        privateDirectory(profile);
        lock.setStaleLockTime(0);
        need(lock.tryLock(0), "CREDENTIAL_HOST_ALREADY_RUNNING");
        auto key = openKey(profile);
        broker =
            std::make_unique<broker::BrokerService>(QDir(profile).filePath("credentials.sqlite"),
                                                    key, QDir(profile).filePath("control.sqlite"));
        OPENSSL_cleanse(key.data(), size_t(key.size()));
        auto registry = [this](const QJsonArray& rows) {
            auto r = broker->readAccountRegistry(rows).get();
            if (!r.ok)
                throw account::AccountError(r.code.toUtf8().constData());
            return r.accountRegistry;
        };
        account = std::make_unique<account::AccountService>(
            accountPath,
            [rpc = daemon](const QString& scope, const QString& method, const QJsonObject& params) {
                return rpc->call(scope, method, params);
            },
            registry);
        const auto hash = QString::fromLatin1(
            QCryptographicHash::hash(profile.toUtf8(), QCryptographicHash::Sha256)
                .toHex()
                .left(24));
#ifdef Q_OS_WIN
        endpoint = "dmash-credential-" + hash;
#else
        auto ipc = QDir::homePath() + "/.cache/dmash-owner-ipc";
        privateDirectory(ipc);
        endpoint = ipc + "/" + hash + ".sock";
#endif
        QLocalServer::removeServer(endpoint);
        server.setSocketOptions(QLocalServer::UserAccessOption);
        need(server.listen(endpoint), "CREDENTIAL_ENDPOINT_UNAVAILABLE");
        QObject::connect(&server, &QLocalServer::newConnection, &poll, [this] {
            while (server.hasPendingConnections())
                accept(server.nextPendingConnection());
        });
        poll.setInterval(20);
        QObject::connect(&poll, &QTimer::timeout, &poll, [this] { complete(); });
        poll.start();
        QFile policyFile(QDir(profile).filePath("node-policy.json"));
        if (policyFile.open(QIODevice::ReadOnly) && policyFile.size() <= 65536)
            policy = QJsonDocument::fromJson(policyFile.readAll()).object();
        QSaveFile locator(QDir(profile).filePath("credential-endpoint.json"));
        need(locator.open(QIODevice::WriteOnly) && locator.setPermissions(ownerOnly),
             "CREDENTIAL_ENDPOINT_UNAVAILABLE");
        auto bytes = QJsonDocument(QJsonObject{{"v", 1}, {"endpoint", endpoint}})
                         .toJson(QJsonDocument::Compact);
        need(locator.write(bytes) == bytes.size() && locator.commit(),
             "CREDENTIAL_ENDPOINT_UNAVAILABLE");
    }
    ~State() {
        broker->cancel();
        account->cancel();
        if (pending.valid())
            pending.wait();
        try {
            auto stopped = broker->fullRootLock().get();
            daemon->clear();
            if (supervisor)
                supervisor->stop();
            if (stopped.ok && stopped.control.phase == "REVOKING")
                broker->confirmTransportStopped(stopped.control).get();
        } catch (...) {
        }
        server.close();
        QFile::remove(QDir(profile).filePath("credential-endpoint.json"));
    }
    bool busy() const { return pending.valid(); }
    void respond(QLocalSocket* socket, const QString& id, const account::AccountResult& r) {
        if (!socket || socket->state() != QLocalSocket::ConnectedState)
            return;
        auto raw = QJsonDocument(
                       QJsonObject{{"v", 1},
                                   {"id", id},
                                   {"ok", r.ok},
                                   {"code", r.code},
                                   {"result", QJsonObject{{"value", r.value}, {"rows", r.rows}}}})
                       .toJson(QJsonDocument::Compact);
        if (raw.size() > 64 * 1024 * 1024 || socket->bytesToWrite() > 64 * 1024 * 1024) {
            socket->abort();
            return;
        }
        QByteArray frame(4, 0);
        qToBigEndian<quint32>(quint32(raw.size()), frame.data());
        frame += raw;
        socket->write(frame);
        raw.fill(0);
        frame.fill(0);
    }
    account::AccountResult status() {
        account::AccountResult r;
        r.ok = true;
        r.value = {
            {"rootLocked", rootLocked},
            {"profileExists", QFileInfo::exists(QDir(profile).filePath("credentials.sqlite"))},
            {"accountSessionActive", !activeAccount.isEmpty()},
            {"account", activeAccount},
            {"accountImportPhase", phase},
            {"nodePolicy", policy},
            {"nodeRunning", supervisor && supervisor->running()},
            {"nodeState", supervisor && supervisor->running()
                              ? "running"
                              : (supervisor ? "stopped" : "unavailable")}};
        if (supervisor && supervisor->running()) {
            try {
                r.value["node"] = daemon->call("status", "node.status", {}, true);
            } catch (...) {
                r.value["nodeState"] = "unavailable";
            }
        }
        return r;
    }
    void accept(QLocalSocket* socket) {
#ifdef Q_OS_UNIX
        ucred peer{};
        socklen_t n = sizeof(peer);
        if (getsockopt(int(socket->socketDescriptor()), SOL_SOCKET, SO_PEERCRED, &peer, &n) ||
            peer.uid != geteuid()) {
            socket->abort();
            socket->deleteLater();
            return;
        }
#elif defined(Q_OS_WIN)
        try {
            windowsLocal::requireSameUserPipe(std::uintptr_t(socket->socketDescriptor()));
            windowsLocal::requirePrivatePipe(std::uintptr_t(socket->socketDescriptor()));
        } catch (...) {
            socket->abort();
            socket->deleteLater();
            return;
        }
#endif
        if (clients.size() >= 16) {
            socket->abort();
            socket->deleteLater();
            return;
        }
        clients.emplace(socket, Client{});
        socket->setReadBufferSize(64 * 1024 * 1024 + 4);
        QObject::connect(socket, &QLocalSocket::readyRead, &poll, [this, socket] { read(socket); });
        QObject::connect(socket, &QLocalSocket::disconnected, &poll, [this, socket] {
            clients.erase(socket);
            socket->deleteLater();
        });
    }
    void read(QLocalSocket* socket) {
        try {
            auto it = clients.find(socket);
            if (it == clients.end())
                return;
            auto& client = it->second;
            while (socket->bytesAvailable()) {
                if (!client.length) {
                    client.input += socket->read(4 - client.input.size());
                    if (client.input.size() < 4)
                        return;
                    client.length = qFromBigEndian<quint32>(client.input.constData());
                    client.input.clear();
                    need(client.length > 0 && client.length <= 64 * 1024 * 1024,
                         "CREDENTIAL_FRAME_LIMIT");
                }
                client.input += socket->read(qint64(client.length) - client.input.size());
                if (client.input.size() < client.length)
                    return;
                QJsonParseError e;
                auto document = QJsonDocument::fromJson(client.input, &e);
                client.input.fill(0);
                client.input.clear();
                client.length = 0;
                need(e.error == QJsonParseError::NoError && document.isObject(),
                     "CREDENTIAL_FRAME_INVALID");
                request(socket, document.object());
            }
        } catch (...) {
            socket->abort();
        }
    }
    account::AccountResult gate(const broker::BrokerResult& opened) {
        if (!opened.ok)
            return failure(opened.code);
        account::AccountResult published;
        if (opened.accountImportPhase == "PENDING") {
            auto inventory = broker->accountImportInventory().get();
            if (!inventory.ok)
                return failure(inventory.code);
            published = account->importProfile(inventory.profileInventory).get();
        } else
            published = account->verifyPublishedImport().get();
        if (published.importProof) {
            need(published.importProof->databasePath() ==
                     QFileInfo(accountPath).canonicalFilePath(),
                 "ACCOUNT_IMPORT_PATH_CONFLICT");
            auto ack = broker->confirmAccountImport(*published.importProof).get();
            if (!ack.ok)
                return failure(ack.code);
            published.value["accountImportPhase"] = ack.accountImportPhase;
        }
        if (!published.ok)
            return published;
        need(published.importProof.has_value(), "ACCOUNT_IMPORT_RECEIPT_MISSING");
        auto rows = account->listAccounts().get();
        rows.value["accountImportPhase"] = "COMMITTED";
        return rows;
    }
    account::AccountResult lockAndStop() {
        ++jobEpoch;
        account->cancel();
        activeAccount = {};
        try {
            auto stopped = broker->fullRootLock().get();
            daemon->clear();
            if (supervisor)
                supervisor->stop();
            if (!stopped.ok)
                throw account::AccountError(stopped.code.toUtf8().constData());
            if (stopped.control.phase == "REVOKING") {
                auto ack = broker->confirmTransportStopped(stopped.control).get();
                need(ack.ok, "NODE_STOP_UNCONFIRMED");
            }
            rootLocked = true;
            account::AccountResult result;
            result.ok = true;
            result.value = {{"rootLocked", true}, {"nodeRunning", false}};
            return result;
        } catch (const std::exception& e) {
            return failure(e.what());
        }
    }
    void request(QLocalSocket* socket, const QJsonObject& request) {
        const auto id = request.value("id").toString(), method = request.value("method").toString();
        auto params = request.value("params").toObject();
        need(request.value("v") == 1 && !id.isEmpty() && id.size() <= 128 && method.size() <= 128,
             "CREDENTIAL_REQUEST_INVALID");
        if (method == "host.status") {
            respond(socket, id, status());
            return;
        }
        if (method == "account.cancel") {
            const bool rootJob =
                busy() && (pendingMethod == "profile.import" || pendingMethod == "root.unlock" ||
                           pendingMethod == "node.enable");
            if (rootJob) {
                respond(socket, id, lockAndStop());
            } else {
                ++jobEpoch;
                account->cancel();
                activeAccount = {};
                account::AccountResult result;
                result.ok = true;
                result.value = {{"rootLocked", rootLocked},
                                {"nodeRunning", supervisor && supervisor->running()},
                                {"accountSessionActive", false}};
                respond(socket, id, result);
            }
            return;
        }
        if (method == "root.lock" || method == "node.disable") {
            respond(socket, id, lockAndStop());
            return;
        }
        if (busy()) {
            respond(socket, id, failure("CREDENTIAL_HOST_BUSY"));
            return;
        }
        if (method == "node.enable") {
            if (!params.contains("endpoints"))
                params["endpoints"] = policy.value("endpoints").toArray();
            if (!params.contains("directEnabled"))
                params["directEnabled"] = policy.value("directEnabled").toBool();
            pendingPolicy = {{"endpoints", params.value("endpoints")},
                             {"directEnabled", params.value("directEnabled")}};
        }
        pendingSocket = socket;
        pendingId = id;
        pendingMethod = method;
        pendingEpoch = jobEpoch;
        pending = std::async(std::launch::async, [this, method, params] {
            JobResult out;
            try {
                if (method == "profile.import") {
                    auto opened =
                        broker
                            ->importProfile(params.value("profile").toObject(),
                                            params.value("pin").toString().toUtf8(),
                                            QDir(profile).filePath("original-profile.backup"))
                            .get();
                    out.result = gate(opened);
                    out.unlocked = out.result.ok;
                } else if (method == "root.unlock") {
                    auto opened = broker->unlock(params.value("pin").toString().toUtf8()).get();
                    out.result = gate(opened);
                    out.unlocked = out.result.ok;
                } else if (method == "node.enable") {
                    need(bool(supervisor), "NODE_HOST_UNAVAILABLE");
                    auto enabled = broker->enableNode(verifyOrMineNodeSeed).get();
                    if (!enabled.ok)
                        out.result = failure(enabled.code);
                    else {
                        out.transport = broker
                                            ->transport(params.value("endpoints").toArray(),
                                                        params.value("directEnabled").toBool())
                                            .get();
                        out.startNode = out.transport.ok;
                        out.result.ok = out.transport.ok;
                        out.result.code = out.transport.code;
                    }
                } else if (method == "account.listAccounts")
                    out.result = account->listAccounts().get();
                else if (method == "account.login")
                    out.result = account
                                     ->login(params.value("identity").toString(),
                                             params.value("password").toString().toUtf8())
                                     .get();
                else if (method == "account.sync")
                    out.result = account->sync().get();
                else if (method == "account.contacts")
                    out.result = account->listContacts().get();
                else if (method == "account.history")
                    out.result = account
                                     ->listHistory(params.value("peer").toString(),
                                                   params.value("before").toInteger(),
                                                   params.value("limit").toInt(100))
                                     .get();
                else if (method == "account.sendText")
                    out.result = account
                                     ->sendText(params.value("peer").toString(),
                                                params.value("operationId").toString(),
                                                params.value("text").toString())
                                     .get();
                else if (method == "account.logout")
                    out.result = account->logout().get();
                else
                    out.result = failure("CREDENTIAL_METHOD_UNKNOWN");
            } catch (const std::exception& e) {
                out.result = failure(e.what());
            } catch (...) {
                out.result = failure("CREDENTIAL_HOST_FAILED");
            }
            return out;
        });
    }
    void complete() {
        if (!pending.valid() ||
            pending.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
            return;
        auto finished = pending.get();
        if (pendingEpoch != jobEpoch) {
            finished.result.ok = false;
            finished.result.code = pendingMethod.startsWith("account.") ? "ACCOUNT_SESSION_CHANGED"
                                                                        : "CREDENTIAL_CANCELLED";
            finished.result.rows = {};
            // Existing accepted value/operation receipts remain truthful; a late
            // cancelled login must never publish a new session or Node install.
            finished.startNode = false;
        }
        if (finished.unlocked && pendingEpoch == jobEpoch)
            rootLocked = false;
        if (finished.result.ok && finished.result.value.contains("accountImportPhase"))
            phase = finished.result.value.value("accountImportPhase").toString();
        if (finished.startNode) {
            try {
                need(broker->isCurrentTransportResult(finished.transport), "CREDENTIAL_CANCELLED");
                auto ready = supervisor->start(finished.transport);
                daemon->install(ready);
                QSaveFile policyFile(QDir(profile).filePath("node-policy.json"));
                need(policyFile.open(QIODevice::WriteOnly) && policyFile.setPermissions(ownerOnly),
                     "NODE_POLICY_STORE_FAILED");
                auto savedPolicy = QJsonDocument(pendingPolicy).toJson(QJsonDocument::Compact);
                need(policyFile.write(savedPolicy) == savedPolicy.size() && policyFile.commit(),
                     "NODE_POLICY_STORE_FAILED");
                policy = pendingPolicy;
                finished.result.value = {{"nodeRunning", true}, {"nodeState", "running"}};
            } catch (const std::exception& e) {
                finished.result = failure(e.what());
                try {
                    auto stopped = broker->fullRootLock().get();
                    rootLocked = true;
                    daemon->clear();
                    supervisor->stop();
                    if (stopped.ok && stopped.control.phase == "REVOKING")
                        broker->confirmTransportStopped(stopped.control).get();
                } catch (...) {
                }
            }
        }
        if (finished.result.ok && pendingMethod == "account.login" && pendingEpoch == jobEpoch)
            activeAccount = finished.result.value;
        if (finished.result.ok && pendingMethod == "account.logout")
            activeAccount = {};
        if (finished.result.ok && pendingMethod == "account.listAccounts")
            finished.result.value["activeAccount"] = activeAccount;
        if (pendingSocket)
            respond(pendingSocket, pendingId, finished.result);
        pendingSocket.clear();
        pendingId.clear();
        pendingMethod.clear();
    }
};
CredentialHost::CredentialHost(QString profile, std::shared_ptr<NodeSupervisor> supervisor)
    : state_(std::make_unique<State>(std::move(profile), std::move(supervisor))) {}
CredentialHost::~CredentialHost() = default;
QString CredentialHost::endpoint() const { return state_->endpoint; }
} // namespace dmash::credential

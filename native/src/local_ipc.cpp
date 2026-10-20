#include "local_ipc.h"
#ifdef Q_OS_WIN
#include "os_windows.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif
#include "crypto_port.h"
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPointer>
#include <QRegularExpression>
#include <QStringDecoder>
#include <QTimer>
#include <QtEndian>
#include <algorithm>
#include <limits>
#include <openssl/crypto.h>
#ifdef Q_OS_UNIX
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace dmash {
namespace {
void need(bool value) {
    if (!value)
        throw std::runtime_error("local channel rejected");
}
QString randomId() { return QString::fromLatin1(CryptoPort::random(32).toHex()); }
bool identifier(const QString& v) {
    static const QRegularExpression r("^[A-Za-z0-9_.-]{1,64}$");
    return r.match(v).hasMatch();
}
bool exact(const QJsonObject& o, QStringList keys) {
    auto actual = o.keys();
    actual.sort();
    keys.sort();
    return actual == keys;
}
qint64 integer(const QJsonValue& v, qint64 lo, qint64 hi) {
    const auto n = v.toDouble(-1);
    need(v.isDouble() && n >= lo && n <= hi && n == qint64(n));
    return qint64(n);
}
} // namespace
QJsonObject parseLocalObject(const QByteArray& raw, qsizetype limit) {
    need(!raw.isEmpty() && raw.size() <= limit);
    QStringDecoder decoder(QStringDecoder::Utf8, QStringConverter::Flag::Stateless);
    const auto decoded = decoder.decode(raw);
    (void)QString(decoded);
    need(!decoder.hasError());
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(raw, &error);
    need(error.error == QJsonParseError::NoError && doc.isObject());
    return doc.object();
}
QByteArray localFrame(const QJsonObject& value, qsizetype limit) {
    const auto raw = QJsonDocument(value).toJson(QJsonDocument::Compact);
    need(raw.size() > 0 && raw.size() <= limit);
    QByteArray out(4, 0);
    qToBigEndian<quint32>(quint32(raw.size()), out.data());
    out += raw;
    return out;
}
struct WipeFrame {
    QByteArray& bytes;
    ~WipeFrame() {
        if (!bytes.isEmpty())
            OPENSSL_cleanse(bytes.data(), size_t(bytes.size()));
    }
};
class LocalIpc::Impl {
  public:
    struct Cap {
        QString principal, role, token;
        qint64 expiry;
    };
    struct Client {
        ~Client() {
            if (!frame.isEmpty())
                OPENSSL_cleanse(frame.data(), size_t(frame.size()));
        }
        QLocalSocket* socket = nullptr;
        QString context;
        QByteArray frame;
        quint32 length = 0;
        bool authenticated = false;
        int cap = -1;
        QHash<QString, QString> pending;
        QHash<QString, qint64> deadlines;
        qint64 started = 0, lastFrame = 0, window = 0;
        int requests = 0, bytes = 0;
    };
    JsActor& actor;
    LocalIpc* owner;
    QLocalServer server;
    QTimer timer;
    QString endpoint;
    qint64 generation;
    QVector<Cap> caps;
    QHash<QLocalSocket*, std::shared_ptr<Client>> clients;
    QHash<QString, QLocalSocket*> replies;
    bool closed = false;
    Impl(JsActor& a, LocalIpc* o, const QString& profile, qint64 g, const QJsonArray& principals)
        : actor(a), owner(o), generation(g) {
#if !defined(Q_OS_UNIX) && !defined(Q_OS_WIN)
        (void)profile;
        (void)principals;
        throw std::runtime_error("local peer ACL unavailable");
#else
        need(g > 0 && principals.size() > 0 && principals.size() <= 16);
        QSet<QString> ids;
        const auto now = QDateTime::currentMSecsSinceEpoch();
        for (const auto& v : principals) {
            need(v.isObject());
            const auto p = v.toObject();
            need(exact(p, {"id", "role", "ttl_seconds"}));
            const auto id = p.value("id").toString(), role = p.value("role").toString();
            need(identifier(id) && !ids.contains(id) && (role == "owner" || role == "broker"));
            ids.insert(id);
            const auto ttl = integer(p.value("ttl_seconds"), 1, role == "broker" ? 86400 : 3600);
            caps.append({id, role, randomId(), now + ttl * 1000});
        }
#ifdef Q_OS_UNIX
        endpoint = QDir(profile).absoluteFilePath("mesh.local");
        const auto encoded = QFile::encodeName(endpoint);
        need(encoded.size() < 104);
        struct stat st {};
        if (::lstat(encoded.constData(), &st) == 0) {
            need(S_ISSOCK(st.st_mode) && st.st_uid == geteuid());
            need(::unlink(encoded.constData()) == 0);
        } else
            need(errno == ENOENT);
#else
        Q_UNUSED(profile);
        endpoint = "dmash-node-" + randomId();
#endif
        server.setSocketOptions(QLocalServer::UserAccessOption);
        need(server.listen(endpoint));
        server.setMaxPendingConnections(8);
        QObject::connect(&server, &QLocalServer::newConnection, owner, [this] {
            while (server.hasPendingConnections()) {
                auto* socket = server.nextPendingConnection();
                try {
                    accept(socket);
                } catch (...) {
                    socket->abort();
                    socket->deleteLater();
                }
            }
        });
        QObject::connect(&timer, &QTimer::timeout, owner, [this] {
            const auto now = QDateTime::currentMSecsSinceEpoch();
            for (const auto& c : clients.values()) {
                if ((!c->authenticated && now - c->started > 5000) ||
                    (c->length && now - c->lastFrame > 10000) ||
                    (c->authenticated && now >= caps[c->cap].expiry) ||
                    std::any_of(c->deadlines.cbegin(), c->deadlines.cend(),
                                [now](qint64 deadline) { return deadline <= now; }))
                    drop(c->socket);
            }
        });
        timer.start(250);
        actor.onLocalReply = [this](const QString& id, const QJsonObject& result) {
            auto* socket = replies.take(id);
            auto c = clients.value(socket);
            if (!c)
                return;
            const auto original = c->pending.take(id);
            c->deadlines.remove(id);
            if (original.isEmpty())
                return;
            QJsonObject response = result;
            response.insert("v", 1);
            response.insert("id", original);
            try {
                send(c, response);
            } catch (...) {
                drop(socket);
            }
        };
#endif
    }
    void accept(QLocalSocket* socket) {
        need(!closed && clients.size() < 8);
#ifdef Q_OS_UNIX
        struct ucred peer {};
        socklen_t length = sizeof(peer);
        need(::getsockopt(int(socket->socketDescriptor()), SOL_SOCKET, SO_PEERCRED, &peer,
                          &length) == 0 &&
             length == sizeof(peer) && peer.uid == geteuid());
#elif defined(Q_OS_WIN)
        windowsLocal::requireSameUserPipe(std::uintptr_t(socket->socketDescriptor()));
        windowsLocal::requirePrivatePipe(std::uintptr_t(socket->socketDescriptor()));
#else
        throw std::runtime_error("local peer unavailable");
#endif
        auto c = std::make_shared<Client>();
        c->socket = socket;
        c->context = randomId();
        c->started = c->lastFrame = c->window = QDateTime::currentMSecsSinceEpoch();
        clients.insert(socket, c);
        socket->setReadBufferSize(2 * (65536 + 4));
        QObject::connect(socket, &QLocalSocket::readyRead, owner, [this, socket] {
            try {
                read(socket);
            } catch (...) {
                drop(socket);
            }
        });
        QObject::connect(socket, &QLocalSocket::disconnected, owner,
                         [this, socket] { drop(socket); });
        if (socket->bytesAvailable())
            read(socket);
    }
    void send(const std::shared_ptr<Client>& c, const QJsonObject& value) {
        const auto frame = localFrame(value);
        qint64 queued = 0;
        for (const auto& other : clients)
            queued += other->socket->bytesToWrite();
        need(c->socket->bytesToWrite() + frame.size() <= 1048576 &&
             queued + frame.size() <= 8388608);
        need(c->socket->write(frame) == frame.size());
    }
    void drop(QLocalSocket* socket) {
        auto c = clients.take(socket);
        if (!c)
            return;
        for (const auto& id : c->pending.keys())
            replies.remove(id);
        if (c->authenticated) {
            try {
                actor.closeLocalSession(c->context);
            } catch (...) {
            }
        }
        socket->disconnect(owner);
        socket->abort();
        socket->deleteLater();
    }
    void request(const std::shared_ptr<Client>& c, const QJsonObject& o) {
        if (c->authenticated)
            need(QDateTime::currentMSecsSinceEpoch() < caps[c->cap].expiry);
        need(exact(o, {"v", "id", "method", "params"}) && o.value("v") == 1 &&
             identifier(o.value("id").toString()) && o.value("method").isString() &&
             o.value("params").isObject());
        const auto id = o.value("id").toString(), method = o.value("method").toString();
        const auto params = o.value("params").toObject();
        need(method.size() <= 64);
        if (!c->authenticated) {
            need(method == "authenticate" && exact(params, {"generation", "capability"}));
            need(integer(params.value("generation"), 1, 9007199254740991LL) == generation);
            const auto token = params.value("capability").toString().toLatin1();
            need(token.size() == 64);
            int found = -1;
            for (int i = 0; i < caps.size(); ++i) {
                const auto expected = caps[i].token.toLatin1();
                if (CRYPTO_memcmp(token.constData(), expected.constData(), 64) == 0)
                    found = i;
            }
            need(found >= 0 && QDateTime::currentMSecsSinceEpoch() < caps[found].expiry);
            c->cap = found;
            actor.openLocalSession(c->context, caps[found].role == "broker");
            c->authenticated = true;
            c->socket->setReadBufferSize(2 * (524288 + 4));
            send(c,
                 {{"v", 1},
                  {"id", id},
                  {"ok", true},
                  {"result", QJsonObject{{"generation", generation}, {"role", caps[found].role}}}});
            return;
        }
        need(method != "authenticate" && c->pending.size() < 4 && replies.size() < 8);
        for (const auto& value : c->pending)
            need(value != id);
        const auto internal = randomId();
        c->pending.insert(internal, id);
        c->deadlines.insert(internal, QDateTime::currentMSecsSinceEpoch() + 30000);
        replies.insert(internal, c->socket);
        actor.dispatchLocal(c->context, internal, method, params);
    }
    void read(QLocalSocket* socket) {
        auto c = clients.value(socket);
        if (!c)
            return;
        while (socket->bytesAvailable() > 0) {
            const auto now = QDateTime::currentMSecsSinceEpoch();
            if (now - c->window >= 1000) {
                c->window = now;
                c->requests = 0;
                c->bytes = 0;
            }
            need(c->bytes <= 4194304);
            if (!c->length) {
                const auto part = socket->read(4 - c->frame.size());
                c->bytes += part.size();
                c->frame += part;
                if (c->frame.size() < 4)
                    return;
                c->length = qFromBigEndian<quint32>(c->frame.constData());
                c->frame.clear();
                const quint32 limit =
                    c->authenticated && caps[c->cap].role == "owner" ? 524288 : 65536;
                need(c->length > 0 && c->length <= limit);
                c->lastFrame = now;
            }
            const auto part = socket->read(c->length - c->frame.size());
            c->bytes += part.size();
            c->frame += part;
            need(c->bytes <= 4194304);
            if (c->frame.size() < c->length)
                return;
            need(++c->requests <= 32);
            auto frame = std::move(c->frame);
            WipeFrame wipe{frame};
            c->frame.clear();
            c->length = 0;
            c->lastFrame = now;
            request(c, parseLocalObject(frame, 524288));
            OPENSSL_cleanse(frame.data(), size_t(frame.size()));
            if (!clients.contains(socket))
                return;
        }
    }
    QJsonObject bootstrapReply() const {
        QJsonArray out;
        for (const auto& c : caps)
            out.append(QJsonObject{{"id", c.principal},
                                   {"role", c.role},
                                   {"token", c.token},
                                   {"expiresAt", c.expiry}});
        return {{"v", 1},
                {"type", "TransportSessionReady"},
                {"endpoint", endpoint},
                {"generation", generation},
                {"capabilities", out},
                {"features", QJsonObject{{"capabilityLeaseRenewal", true}}}};
    }
    QJsonObject renewCapability(const QString& principal, qint64 ttl) {
        need(!closed);
        int index = -1;
        for (int i = 0; i < caps.size(); ++i)
            if (caps[i].principal == principal)
                index = i;
        need(index >= 0 && ttl >= 1 && ttl <= (caps[index].role == "broker" ? 86400 : 3600));
        for (const auto& c : clients.values())
            if (c->authenticated && c->cap == index)
                drop(c->socket);
        auto& cap = caps[index];
        cap.token.fill(QChar(0));
        cap.token = randomId();
        cap.expiry = QDateTime::currentMSecsSinceEpoch() + ttl * 1000;
        return {{"id", cap.principal},
                {"role", cap.role},
                {"token", cap.token},
                {"expiresAt", cap.expiry},
                {"generation", generation}};
    }
    QJsonObject extendCapabilityLease(const QString& principal, qint64 ttl) {
        need(!closed);
        int index = -1;
        for (int i = 0; i < caps.size(); ++i)
            if (caps[i].principal == principal)
                index = i;
        need(index >= 0 && ttl >= 1 && ttl <= (caps[index].role == "broker" ? 86400 : 3600));
        auto& cap = caps[index];
        cap.expiry = qMax(cap.expiry, QDateTime::currentMSecsSinceEpoch() + ttl * 1000);
        return {{"id", cap.principal}, {"role", cap.role}, {"token", cap.token},
                {"expiresAt", cap.expiry}, {"generation", generation}};
    }
    void close() {
        if (closed)
            return;
        closed = true;
        actor.onLocalReply = {};
        timer.stop();
        server.close();
        for (auto* socket : clients.keys())
            drop(socket);
        for (auto& c : caps)
            c.token.fill(QChar(0));
        caps.clear();
    }
};
LocalIpc::LocalIpc(JsActor& a, const QString& p, qint64 g, const QJsonArray& principals,
                   QObject* parent)
    : QObject(parent), impl_(std::make_unique<Impl>(a, this, p, g, principals)) {}
LocalIpc::~LocalIpc() { close(); }
QJsonObject LocalIpc::bootstrapReply() const { return impl_->bootstrapReply(); }
QJsonObject LocalIpc::renewCapability(const QString& principal, qint64 ttl) {
    return impl_->renewCapability(principal, ttl);
}
QJsonObject LocalIpc::extendCapabilityLease(const QString& principal, qint64 ttl) {
    return impl_->extendCapabilityLease(principal, ttl);
}
void LocalIpc::close() {
    if (impl_)
        impl_->close();
}
} // namespace dmash
#ifdef Q_OS_UNIX
#include <fcntl.h>
#include <poll.h>
#endif
namespace dmash {
BootstrapInstall readBootstrapInstall(qintptr fd) {
#ifdef Q_OS_WIN
    windowsLocal::requireSameUserPipe(std::uintptr_t(fd));
    windowsLocal::requirePrivatePipe(std::uintptr_t(fd));
    HANDLE handle = reinterpret_cast<HANDLE>(fd);
    need(SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0));
    const auto deadline = QDateTime::currentMSecsSinceEpoch() + 5000;
    auto receive = [&](qsizetype count) {
        QByteArray result;
        while (result.size() < count) {
            const auto left = deadline - QDateTime::currentMSecsSinceEpoch();
            need(left > 0); DWORD available = 0;
            need(PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr));
            if (!available) { Sleep(DWORD(qMin<qint64>(left, 5))); continue; }
            char bytes[4096]; DWORD read = 0;
            const auto length = DWORD(qMin<qsizetype>(qMin<qsizetype>(sizeof(bytes), available), count - result.size()));
            OVERLAPPED overlapped{}; overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            need(overlapped.hEvent != nullptr);
            const BOOL immediate = ReadFile(handle, bytes, length, &read, &overlapped);
            bool completed = bool(immediate);
            if (!immediate && GetLastError() == ERROR_IO_PENDING) {
                completed = WaitForSingleObject(overlapped.hEvent, DWORD(left)) == WAIT_OBJECT_0;
                if (!completed) { CancelIoEx(handle, &overlapped); WaitForSingleObject(overlapped.hEvent, INFINITE); }
                else completed = bool(GetOverlappedResult(handle, &overlapped, &read, FALSE));
            }
            CloseHandle(overlapped.hEvent);
            need(completed && read > 0);
            result.append(bytes, read); OPENSSL_cleanse(bytes, sizeof(bytes));
        }
        return result;
    };
#elif defined(Q_OS_UNIX)
    need(fd >= 3 && fd <= std::numeric_limits<int>::max());
    struct ucred peer {};
    socklen_t size = sizeof(peer);
    need(::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 && size == sizeof(peer) &&
         peer.uid == geteuid());
    int kind = 0;
    size = sizeof(kind);
    need(::getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &size) == 0 && kind == SOCK_STREAM);
    sockaddr_storage address{};
    size = sizeof(address);
    need(::getpeername(fd, reinterpret_cast<sockaddr*>(&address), &size) == 0 &&
         address.ss_family == AF_UNIX);
    need(::fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
    const auto deadline = QDateTime::currentMSecsSinceEpoch() + 5000;
    auto receive = [&](qsizetype count) {
        QByteArray result;
        result.reserve(count);
        while (result.size() < count) {
            const auto left = deadline - QDateTime::currentMSecsSinceEpoch();
            need(left > 0);
            pollfd p{int(fd), POLLIN, 0};
            const auto ready = ::poll(&p, 1, int(left));
            if (ready < 0 && errno == EINTR)
                continue;
            need(ready > 0 && (p.revents & POLLIN));
            char bytes[4096];
            const auto n =
                ::recv(fd, bytes, size_t(qMin<qsizetype>(sizeof(bytes), count - result.size())),
                       MSG_DONTWAIT);
            if (n < 0 && (errno == EINTR || errno == EAGAIN))
                continue;
            need(n > 0);
            result.append(bytes, n);
            OPENSSL_cleanse(bytes, sizeof(bytes));
        }
        return result;
    };
#else
    (void)fd;
    throw std::runtime_error("bootstrap peer unavailable");
#endif
    const auto header = receive(4);
    const auto length = qFromBigEndian<quint32>(header.constData());
    need(length > 0 && length <= 65536);
    auto raw = receive(length);
    struct Wipe {
        QByteArray& b;
        ~Wipe() {
            if (!b.isEmpty())
                OPENSSL_cleanse(b.data(), size_t(b.size()));
        }
    } wipe{raw};
    auto o = parseLocalObject(raw, 65536);
    need(exact(o, {"v", "type", "request_id", "generation", "effective_policy_revision",
                   "transport_bundle", "principals"}) &&
         o.value("v") == 1 && o.value("type") == "InstallTransportSession" &&
         identifier(o.value("request_id").toString()) && o.value("transport_bundle").isObject() &&
         o.value("principals").isArray());
    BootstrapInstall result;
    result.bundle = TransportBundle::parse(o.value("transport_bundle").toObject());
    need(integer(o.value("generation"), 1, 9007199254740991LL) == qint64(result.bundle.generation));
    result.policyRevision = integer(o.value("effective_policy_revision"), 1, 9007199254740991LL);
    result.principals = o.value("principals").toArray();
    result.requestId = o.value("request_id").toString();
    return result;
}
} // namespace dmash

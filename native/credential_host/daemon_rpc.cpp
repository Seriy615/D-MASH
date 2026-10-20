#include "daemon_rpc.h"
#include "legacy_kyber.h"
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QtEndian>
#ifdef Q_OS_WIN
#include <windows.h>
#else
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif
namespace dmash::credential {
namespace {
void need(bool b, const char* code = "ACCOUNT_TRANSPORT_FAILED") {
    if (!b)
        throw account::AccountError(code);
}
void closeSocket(qintptr s) {
#ifdef Q_OS_WIN
    CloseHandle(reinterpret_cast<HANDLE>(s));
#else
    ::close(int(s));
#endif
}
qintptr connectSocket(const QString& endpoint) {
#ifdef Q_OS_WIN
    auto name =
        endpoint.startsWith("\\\\.\\pipe\\") ? endpoint : QString("\\\\.\\pipe\\") + endpoint;
    need(WaitNamedPipeW(reinterpret_cast<LPCWSTR>(name.utf16()), 5000),
         "ACCOUNT_TRANSPORT_UNAVAILABLE");
    HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(name.utf16()), GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    need(h != INVALID_HANDLE_VALUE, "ACCOUNT_TRANSPORT_UNAVAILABLE");
    return qintptr(h);
#else
    auto path = QFile::encodeName(endpoint);
    need(path.size() < int(sizeof(sockaddr_un::sun_path)), "ACCOUNT_TRANSPORT_UNAVAILABLE");
    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    need(fd >= 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path.constData(), size_t(path.size() + 1));
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        throw account::AccountError("ACCOUNT_TRANSPORT_UNAVAILABLE");
    }
    ucred peer{};
    socklen_t n = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &n) || peer.uid != geteuid()) {
        ::close(fd);
        throw account::AccountError("ACCOUNT_TRANSPORT_PEER_REJECTED");
    }
    return fd;
#endif
}
void transfer(qintptr handle, char* data, int size, bool write) {
    int offset = 0;
    while (offset < size) {
#ifdef Q_OS_WIN
        OVERLAPPED op{};
        op.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        need(op.hEvent != nullptr);
        DWORD count = 0;
        BOOL done = write ? WriteFile(reinterpret_cast<HANDLE>(handle), data + offset,
                                      DWORD(size - offset), &count, &op)
                          : ReadFile(reinterpret_cast<HANDLE>(handle), data + offset,
                                     DWORD(size - offset), &count, &op);
        if (!done && GetLastError() == ERROR_IO_PENDING) {
            if (WaitForSingleObject(op.hEvent, 5000) != WAIT_OBJECT_0) {
                CancelIoEx(reinterpret_cast<HANDLE>(handle), &op);
                WaitForSingleObject(op.hEvent, INFINITE);
                CloseHandle(op.hEvent);
                throw account::AccountError("ACCOUNT_TRANSPORT_TIMEOUT");
            }
            done = GetOverlappedResult(reinterpret_cast<HANDLE>(handle), &op, &count, FALSE);
        }
        CloseHandle(op.hEvent);
        need(done && count > 0);
        offset += int(count);
#else
        pollfd p{int(handle), short(write ? POLLOUT : POLLIN), 0};
        need(::poll(&p, 1, 5000) == 1, "ACCOUNT_TRANSPORT_TIMEOUT");
        auto n = write ? ::send(int(handle), data + offset, size_t(size - offset), MSG_NOSIGNAL)
                       : ::recv(int(handle), data + offset, size_t(size - offset), 0);
        need(n > 0);
        offset += int(n);
#endif
    }
}
QJsonObject request(qintptr socket, const QString& method, const QJsonObject& params) {
    auto bytes = QJsonDocument(
                     QJsonObject{{"v", 1}, {"id", "owner"}, {"method", method}, {"params", params}})
                     .toJson(QJsonDocument::Compact);
    need(bytes.size() <= 524288, "ACCOUNT_TRANSPORT_FRAME_LIMIT");
    QByteArray frame(4, 0);
    qToBigEndian<quint32>(quint32(bytes.size()), frame.data());
    frame += bytes;
    transfer(socket, frame.data(), int(frame.size()), true);
    frame.fill(0);
    bytes.fill(0);
    QByteArray header(4, 0);
    transfer(socket, header.data(), 4, false);
    auto length = qFromBigEndian<quint32>(header.constData());
    need(length > 0 && length <= 524288, "ACCOUNT_TRANSPORT_FRAME_LIMIT");
    QByteArray raw(int(length), Qt::Uninitialized);
    transfer(socket, raw.data(), int(length), false);
    QJsonParseError error;
    auto reply = QJsonDocument::fromJson(raw, &error).object();
    raw.fill(0);
    need(error.error == QJsonParseError::NoError && reply.value("id") == "owner");
    if (!reply.value("ok").toBool()) {
        auto code = reply.value("code").toString();
        if (code.isEmpty())
            code = reply.value("error").toObject().value("code").toString();
        if (code.isEmpty())
            code = "ACCOUNT_TRANSPORT_REJECTED";
        throw account::AccountError(code.toUtf8().constData());
    }
    return reply.value("result").toObject();
}
} // namespace
DaemonRpc::~DaemonRpc() { clear(); }
void DaemonRpc::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [scope, fd] : sockets_)
        closeSocket(fd);
    sockets_.clear();
    ready_ = {};
}
void DaemonRpc::install(const QJsonObject& ready) {
    clear();
    std::lock_guard<std::mutex> lock(mutex_);
    ready_ = ready;
}
QJsonObject DaemonRpc::call(const QString& scope, const QString& method, const QJsonObject& params,
                            bool broker) {
    std::lock_guard<std::mutex> lock(mutex_);
    need(!ready_.isEmpty(), "ACCOUNT_TRANSPORT_UNAVAILABLE");
    const auto key = (broker ? QString("broker:") : QString("owner:")) + scope;
    auto found = sockets_.find(key);
    if (found == sockets_.end()) {
        const auto role = broker ? QString("broker") : QString("owner");
        QString token;
        for (const auto& value : ready_.value("capabilities").toArray()) {
            const auto row = value.toObject();
            if (row.value("role") == role)
                token = row.value("token").toString();
        }
        need(!token.isEmpty(), "ACCOUNT_TRANSPORT_UNAVAILABLE");
        auto fd = connectSocket(ready_.value("endpoint").toString());
        try {
            request(fd, "authenticate",
                    {{"generation", ready_.value("generation")}, {"capability", token}});
        } catch (...) {
            closeSocket(fd);
            throw;
        }
        found = sockets_.emplace(key, fd).first;
    }
    try {
        return request(found->second, method, params);
    } catch (...) {
        closeSocket(found->second);
        sockets_.erase(found);
        throw;
    }
}
} // namespace dmash::credential

#include "supervisor.h"
#include "legacy_kyber.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QtEndian>
#ifdef Q_OS_UNIX
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#ifdef Q_OS_WIN
#include <windows.h>
#endif
namespace dmash::credential {
namespace {
void need(bool b, const char* code) {
    if (!b)
        throw account::AccountError(code);
}
QJsonObject receive(QLocalSocket& socket) {
    auto exact = [&](int n) {
        QByteArray b;
        while (b.size() < n) {
            if (!socket.bytesAvailable())
                need(socket.waitForReadyRead(5000), "NODE_BOOTSTRAP_FAILED");
            b += socket.read(n - b.size());
        }
        return b;
    };
    auto header = exact(4);
    auto n = qFromBigEndian<quint32>(header.constData());
    need(n > 0 && n <= 65536, "NODE_BOOTSTRAP_FAILED");
    auto raw = exact(int(n));
    QJsonParseError e;
    auto result = QJsonDocument::fromJson(raw, &e).object();
    raw.fill(0);
    need(e.error == QJsonParseError::NoError, "NODE_BOOTSTRAP_FAILED");
    return result;
}
} // namespace
Supervisor::Supervisor(QString binary, QString profile)
    : binary_(std::move(binary)), profile_(std::move(profile)) {}
Supervisor::~Supervisor() {
    try {
        stop();
    } catch (...) {
    }
}
bool Supervisor::running() const {
#ifdef Q_OS_WIN
    return child_ &&
           WaitForSingleObject(reinterpret_cast<HANDLE>(child_->process), 0) == WAIT_TIMEOUT;
#else
    return child_ && child_->state() != QProcess::NotRunning;
#endif
}
void Supervisor::stop() {
    lease_.reset();
    if (child_) {
#ifdef Q_OS_WIN
        auto handle = reinterpret_cast<HANDLE>(child_->process);
        if (WaitForSingleObject(handle, 5000) == WAIT_TIMEOUT) {
            TerminateProcess(handle, 1);
            need(WaitForSingleObject(handle, 5000) == WAIT_OBJECT_0, "NODE_STOP_UNCONFIRMED");
        }
#else
        if (child_->state() != QProcess::NotRunning && !child_->waitForFinished(5000)) {
            child_->kill();
            need(child_->waitForFinished(5000), "NODE_STOP_UNCONFIRMED");
        }
#endif
        child_.reset();
    }
}
QJsonObject Supervisor::start(const broker::BrokerResult& session) {
    need(!running(), "NODE_ALREADY_RUNNING");
    need(QFileInfo(binary_).isExecutable(), "NODE_HOST_UNAVAILABLE");
    stop();
    need(QDir().mkpath(profile_), "NODE_PROFILE_UNAVAILABLE");
#ifndef Q_OS_WIN
    need(QFile::setPermissions(profile_, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                             QFileDevice::ExeOwner),
         "NODE_PROFILE_UNAVAILABLE");
    int pair[2];
    need(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0, "NODE_BOOTSTRAP_FAILED");
    child_ = std::make_unique<QProcess>();
    QProcess::UnixProcessParameters options;
    options.flags = QProcess::UnixProcessFlag::CloseFileDescriptors;
    options.lowestFileDescriptorToClose = 4;
    child_->setUnixProcessParameters(options);
    const int parent = pair[0], child = pair[1];
    child_->setChildProcessModifier([parent, child] {
        if (child != 3) {
            if (::dup2(child, 3) < 0)
                _exit(126);
        } else {
            int flags = fcntl(3, F_GETFD);
            if (flags < 0 || fcntl(3, F_SETFD, flags & ~FD_CLOEXEC) < 0)
                _exit(126);
        }
        if (parent != 3)
            ::close(parent);
        if (child != 3)
            ::close(child);
    });
    child_->setProgram(binary_);
    child_->setArguments({"--profile", profile_, "--bootstrap-fd", "3"});
    child_->setStandardOutputFile(QProcess::nullDevice());
    child_->setStandardErrorFile(QProcess::nullDevice());
    child_->start();
    ::close(child);
    if (!child_->waitForStarted(5000)) {
        ::close(parent);
        child_.reset();
        throw account::AccountError("NODE_SPAWN_FAILED");
    }
    lease_ = std::make_unique<QLocalSocket>();
    if (!lease_->setSocketDescriptor(parent, QLocalSocket::ConnectedState, QIODevice::ReadWrite)) {
        ::close(parent);
        stop();
        throw account::AccountError("NODE_BOOTSTRAP_FAILED");
    }
#else
    child_ = std::make_unique<dmash::windowsLocal::ChildProcess>(dmash::windowsLocal::spawnDaemon(
        binary_.toStdWString(), {L"--profile", profile_.toStdWString()}));
    lease_ = std::make_unique<QLocalSocket>();
    need(lease_->setSocketDescriptor(qintptr(child_->releaseParentPipe()),
                                     QLocalSocket::ConnectedState, QIODevice::ReadWrite),
         "NODE_BOOTSTRAP_FAILED");
#endif
    try {
        QJsonObject install{
            {"v", 1},
            {"type", "InstallTransportSession"},
            {"request_id", "credential-owner"},
            {"generation", double(session.control.generation)},
            {"effective_policy_revision", double(session.control.policyRevision)},
            {"transport_bundle", session.transportBundle},
            {"principals",
             QJsonArray{
                 QJsonObject{
                     {"id", "credential-owner"}, {"role", "broker"}, {"ttl_seconds", 86400}},
                 QJsonObject{{"id", "account-owner"}, {"role", "owner"}, {"ttl_seconds", 3600}}}}};
        auto raw = QJsonDocument(install).toJson(QJsonDocument::Compact);
        QByteArray frame(4, 0);
        qToBigEndian<quint32>(quint32(raw.size()), frame.data());
        frame += raw;
        need(lease_->write(frame) == frame.size() && lease_->waitForBytesWritten(5000),
             "NODE_BOOTSTRAP_FAILED");
        frame.fill(0);
        raw.fill(0);
        auto ready = receive(*lease_);
        need(ready.value("type") == "TransportSessionReady" &&
                 ready.value("generation").toInteger() == qint64(session.control.generation),
             "NODE_BOOTSTRAP_FAILED");
        return ready;
    } catch (...) {
        stop();
        throw;
    }
}
} // namespace dmash::credential

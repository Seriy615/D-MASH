#include "supervisor.h"
#include "legacy_kyber.h"
#include "node_miner.h"
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSaveFile>
#include <QThread>
#include <QtEndian>
#ifdef Q_OS_UNIX
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
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
            if (!socket.bytesAvailable() && !socket.waitForReadyRead(5000))
                throw account::AccountError(socket.state() == QLocalSocket::UnconnectedState
                                               ? "NODE_BOOTSTRAP_CHILD_CLOSED"
                                               : "NODE_BOOTSTRAP_READ_TIMEOUT");
            b += socket.read(n - b.size());
        }
        return b;
    };
    auto header = exact(4);
    auto n = qFromBigEndian<quint32>(header.constData());
    need(n > 0 && n <= 65536, "NODE_BOOTSTRAP_FRAME_INVALID");
    auto raw = exact(int(n));
    QJsonParseError e;
    auto result = QJsonDocument::fromJson(raw, &e).object();
    raw.fill(0);
    need(e.error == QJsonParseError::NoError, "NODE_BOOTSTRAP_FRAME_INVALID");
    return result;
}
#ifdef Q_OS_UNIX
struct ProcessIdentity {
    QString stamp;
    char state = 0;
};
ProcessIdentity processIdentity(qint64 pid) {
    QFile stat(QString("/proc/%1/stat").arg(pid));
    if (!stat.open(QIODevice::ReadOnly)) {
        need(!QFileInfo(stat).exists(), "NODE_PROCESS_IDENTITY_UNAVAILABLE");
        return {};
    }
    const auto raw = stat.readAll();
    const auto close = raw.lastIndexOf(')');
    need(close > 0, "NODE_PROCESS_IDENTITY_UNAVAILABLE");
    const auto fields = raw.mid(close + 2).split(' ');
    need(fields.size() > 19 && !fields[0].isEmpty(), "NODE_PROCESS_IDENTITY_UNAVAILABLE");
    QFile boot("/proc/sys/kernel/random/boot_id");
    need(boot.open(QIODevice::ReadOnly), "NODE_PROCESS_IDENTITY_UNAVAILABLE");
    return {QString::fromLatin1(boot.readAll().trimmed() + ":" + fields[19]), fields[0][0]};
}
#endif
#ifdef Q_OS_WIN
QString processIdentity(HANDLE process) {
    FILETIME created, exited, kernel, user;
    need(GetProcessTimes(process, &created, &exited, &kernel, &user),
         "NODE_PROCESS_IDENTITY_UNAVAILABLE");
    const auto value = (quint64(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    return "win:" + QString::number(value);
}
#endif
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
void Supervisor::writeChildReceipt(const broker::BrokerResult& session) {
    qint64 pid = 0;
    QString stamp;
#ifdef Q_OS_WIN
    pid = child_->pid;
    stamp = processIdentity(reinterpret_cast<HANDLE>(child_->process));
#else
    pid = child_->processId();
    stamp = processIdentity(pid).stamp;
#endif
    need(pid > 0 && !stamp.isEmpty(), "NODE_PROCESS_IDENTITY_UNAVAILABLE");
    QJsonObject receipt{
        {"v", 1},
        {"pid", pid},
        {"processStart", stamp},
        {"deviceId", session.deviceId},
        {"executable", QFileInfo(binary_).canonicalFilePath()},
        {"nodeId", nodePublicId(QByteArray::fromHex(
                       session.transportBundle.value("nodeSeed").toString().toLatin1()))},
        {"generation", double(session.control.generation)},
        {"policyRevision", double(session.control.policyRevision)}};
    QSaveFile output(QDir(profile_).filePath("supervisor-child.json"));
    need(output.open(QIODevice::WriteOnly) &&
             output.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner),
         "NODE_RECEIPT_STORE_FAILED");
    const auto raw = QJsonDocument(receipt).toJson(QJsonDocument::Compact);
    need(output.write(raw) == raw.size() && output.flush(), "NODE_RECEIPT_STORE_FAILED");
#ifdef Q_OS_UNIX
    need(::fsync(output.handle()) == 0, "NODE_RECEIPT_STORE_FAILED");
#endif
    need(output.commit(), "NODE_RECEIPT_STORE_FAILED");
#ifdef Q_OS_UNIX
    const auto directory = QFile::encodeName(profile_);
    int fd = ::open(directory.constData(), O_RDONLY | O_DIRECTORY);
    need(fd >= 0, "NODE_RECEIPT_STORE_FAILED");
    const int result = ::fsync(fd);
    ::close(fd);
    need(result == 0, "NODE_RECEIPT_STORE_FAILED");
#endif
}
bool Supervisor::provePreviousStopped(const broker::ControlState& state,
                                      broker::RootCodec::Current current) {
    need(current && current(), "CREDENTIAL_CANCELLED");
    need(!QFileInfo(profile_).isSymLink(), "NODE_PROFILE_UNAVAILABLE");
    const auto path = QDir(profile_).filePath("supervisor-child.json");
    if (!QFileInfo::exists(path)) {
        // No scoped bundle is delivered until a durable child receipt exists.
        // Existing unreceipted native databases need explicit recovery.
        const auto entries =
            QDir(profile_).entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden);
        for (const auto& name : entries)
            if (!name.startsWith("supervisor-child.json.") &&
                !name.startsWith(".supervisor-child.json."))
                return false;
        return true;
    }
    need(QFileInfo(path).isFile() && !QFileInfo(path).isSymLink(), "NODE_RECEIPT_INVALID");
    QFile input(path);
    need(input.open(QIODevice::ReadOnly) && input.size() <= 65536, "NODE_RECEIPT_INVALID");
    QJsonParseError error;
    const auto receipt = QJsonDocument::fromJson(input.readAll(), &error).object();
    const auto pid = receipt.value("pid").toInteger();
    const auto stamp = receipt.value("processStart").toString();
    need(error.error == QJsonParseError::NoError && receipt.value("v") == 1 &&
             receipt.value("deviceId") == state.deviceId && pid > 0 && pid <= 0xffffffffLL &&
             receipt.value("generation").toInteger() >= 1 &&
             receipt.value("generation").toInteger() <= 9007199254740991LL &&
             receipt.value("policyRevision").toInteger() >= 1 &&
             receipt.value("policyRevision").toInteger() <= 9007199254740991LL,
         "NODE_RECEIPT_INVALID");
#ifdef Q_OS_WIN
    need(QRegularExpression("^win:[0-9]+$").match(stamp).hasMatch(), "NODE_RECEIPT_INVALID");
    HANDLE process = OpenProcess(
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, DWORD(pid));
    if (!process)
        return GetLastError() == ERROR_INVALID_PARAMETER;
    struct Guard {
        HANDLE process;
        ~Guard() { CloseHandle(process); }
    } guard{process};
    if (processIdentity(process) != stamp)
        return true;
    for (int elapsed = 0; elapsed < 5000; elapsed += 20) {
        need(current(), "CREDENTIAL_CANCELLED");
        if (WaitForSingleObject(process, 20) == WAIT_OBJECT_0)
            return true;
    }
    need(current(), "CREDENTIAL_CANCELLED");
    need(TerminateProcess(process, 1), "NODE_PREVIOUS_EXIT_UNCONFIRMED");
    for (int elapsed = 0; elapsed < 5000; elapsed += 20) {
        need(current(), "CREDENTIAL_CANCELLED");
        if (WaitForSingleObject(process, 20) == WAIT_OBJECT_0)
            return true;
    }
#else
    need(QRegularExpression("^[0-9a-f-]{36}:[0-9]+$").match(stamp).hasMatch(),
         "NODE_RECEIPT_INVALID");
    for (int elapsed = 0; elapsed < 5000; elapsed += 20) {
        need(current(), "CREDENTIAL_CANCELLED");
        const auto actual = processIdentity(pid);
        if (actual.stamp.isEmpty() || actual.stamp != stamp || actual.state == 'Z')
            return true;
        need(QFileInfo(QString("/proc/%1/exe").arg(pid)).symLinkTarget() ==
                 receipt.value("executable").toString(),
             "NODE_RECEIPT_PROCESS_MISMATCH");
        QThread::msleep(20);
    }
#ifdef SYS_pidfd_open
    const int process = int(::syscall(SYS_pidfd_open, int(pid), 0));
    if (process < 0)
        return processIdentity(pid).stamp != stamp;
    struct Guard {
        int fd;
        ~Guard() { ::close(fd); }
    } guard{process};
    if (processIdentity(pid).stamp != stamp)
        return true;
    for (const auto signal : {SIGTERM, SIGKILL}) {
        need(current(), "CREDENTIAL_CANCELLED");
#ifdef SYS_pidfd_send_signal
        if (::syscall(SYS_pidfd_send_signal, process, signal, nullptr, 0) != 0) {
            pollfd exited{process, POLLIN, 0};
            return ::poll(&exited, 1, 0) > 0;
        }
#else
        return false;
#endif
        for (int elapsed = 0; elapsed < 2500; elapsed += 20) {
            need(current(), "CREDENTIAL_CANCELLED");
            pollfd p{process, POLLIN, 0};
            if (::poll(&p, 1, 20) > 0)
                return true;
        }
    }
#endif
#endif
    return false;
}
QJsonObject Supervisor::takeStoppedFloors() {
    auto result = stoppedFloors_;
    stoppedFloors_ = {};
    return result;
}
QJsonArray Supervisor::renewCapabilities() {
    need(running() && bool(lease_), "NODE_HOST_UNAVAILABLE");
    need(leaseRenewalSupported_, "NODE_LEASE_RENEWAL_UNSUPPORTED");
    QJsonArray renewed;
    for (const auto& principal : {QString("credential-owner"), QString("account-owner")}) {
        const auto requestId = principal + "-renew";
        QJsonObject request{{"v", 1},
                            {"type", "RenewCapabilityLease"},
                            {"request_id", requestId},
                            {"principal", principal},
                            {"ttl_seconds", principal == "credential-owner" ? 86400 : 3600}};
        auto raw = QJsonDocument(request).toJson(QJsonDocument::Compact);
        QByteArray frame(4, 0);
        qToBigEndian<quint32>(quint32(raw.size()), frame.data());
        frame += raw;
        need(lease_->write(frame) == frame.size() && lease_->waitForBytesWritten(5000),
             "NODE_CAPABILITY_RENEWAL_FAILED");
        frame.fill(0);
        raw.fill(0);
        auto reply = receive(*lease_);
        need(reply.value("type") == "CapabilityLeaseRenewed" &&
                 reply.value("request_id") == requestId && reply.value("id") == principal,
             "NODE_CAPABILITY_RENEWAL_FAILED");
        renewed.append(reply);
    }
    return renewed;
}
QJsonObject Supervisor::start(const broker::BrokerResult& session) {
    need(!running(), "NODE_ALREADY_RUNNING");
    need(QFileInfo(binary_).isExecutable(), "NODE_HOST_UNAVAILABLE");
    stop();
    stoppedFloors_ = {};
    need(!QFileInfo(profile_).isSymLink(), "NODE_PROFILE_UNAVAILABLE");
    if (QFileInfo::exists(QDir(profile_).filePath("supervisor-child.json")))
        need(provePreviousStopped(session.control, [] { return true; }),
             "NODE_PREVIOUS_EXIT_UNCONFIRMED");
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
    QJsonObject candidateFloors;
    try {
        // Publication precedes every credential byte sent to the child.
        writeChildReceipt(session);
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
             "NODE_BOOTSTRAP_WRITE_FAILED");
        frame.fill(0);
        raw.fill(0);
        auto ready = receive(*lease_);
        if (ready.value("type") == "STALE_FLOOR") {
            const auto generation = ready.value("minTransportGeneration").toInteger();
            const auto policy = ready.value("minPolicyRevision").toInteger();
            need(ready.value("v") == 1 && ready.value("request_id") == "credential-owner" &&
                     generation >= 1 && generation <= 9007199254740991LL && policy >= 1 &&
                     policy <= 9007199254740991LL,
                 "NODE_BOOTSTRAP_FAILED");
            candidateFloors = ready;
            throw account::AccountError("NODE_STALE_FLOOR");
        }
        const auto ownerEpoch = ready.value("generation").toInteger();
        need(ready.value("v") == 1 && ready.value("type") == "TransportSessionReady" &&
                 ready.value("request_id") == "credential-owner" && ownerEpoch >= 1 &&
                 ownerEpoch <= 9007199254740991LL,
             "NODE_BOOTSTRAP_RESPONSE_INVALID");
        // This generation is the distinct durable owner-acquisition epoch.
        // The host verifies transport generation/revision via authenticated node.status.
        leaseRenewalSupported_ =
            ready.value("features").toObject().value("capabilityLeaseRenewal").toBool();
        return ready;
    } catch (...) {
        stop();
        // stop() confirmed this exact owned process exited before publication.
        stoppedFloors_ = candidateFloors;
        throw;
    }
}
} // namespace dmash::credential

#include "broker_service.h"
#include <QFileInfo>
#include <openssl/crypto.h>
namespace dmash::broker {
namespace {
struct Pin {
    QByteArray bytes;
    explicit Pin(QByteArray b) : bytes(std::move(b)) { bytes.detach(); }
    ~Pin() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
BrokerResult success(const CredentialSnapshot& s) {
    BrokerResult r;
    r.ok = true;
    r.revision = s.revision;
    r.deviceId = s.deviceId;
    r.cleanupPending = s.cleanupPending;
    r.accountImportPhase = s.accountImportPhase;
    r.accountDatabasePath = s.accountDatabasePath;
    return r;
}
void need(bool b, const char* c) {
    if (!b)
        throw Error(c);
}
} // namespace
BrokerService::BrokerService(QString path, QByteArray key, QString control)
    : path_(std::move(path)), controlPath_(std::move(control)), key_(std::move(key)) {
    key_.detach();
    worker_ = std::thread([this] {
        for (;;) {
            std::function<void()> f;
            {
                std::unique_lock<std::mutex> l(mutex_);
                ready_.wait(l, [this] { return stopping_ || eraseRequested_ || !queue_.empty(); });
                if (eraseRequested_.exchange(false))
                    root_.reset();
                if (queue_.empty()) {
                    if (stopping_)
                        break;
                    continue;
                }
                f = std::move(queue_.front());
                queue_.pop_front();
            }
            f();
        }
        root_.reset();
        control_.reset();
        store_.reset();
    });
}
BrokerService::~BrokerService() {
    cancel();
    {
        std::lock_guard<std::mutex> l(mutex_);
        stopping_ = true;
    }
    ready_.notify_all();
    worker_.join();
    OPENSSL_cleanse(key_.data(), key_.size());
}
std::future<BrokerResult> BrokerService::enqueue(std::function<BrokerResult()> f) {
    auto task = std::make_shared<std::packaged_task<BrokerResult()>>([f = std::move(f)] {
        try {
            return f();
        } catch (const Error& e) {
            BrokerResult r;
            r.code = QString::fromLatin1(e.what());
            return r;
        } catch (...) {
            BrokerResult r;
            r.code = "BROKER_OPERATION_FAILED";
            return r;
        }
    });
    auto result = task->get_future();
    {
        std::lock_guard<std::mutex> l(mutex_);
        if (stopping_ || queue_.size() >= 16) {
            std::promise<BrokerResult> p;
            BrokerResult r;
            r.code = "BROKER_BUSY";
            p.set_value(r);
            return p.get_future();
        }
        queue_.push_back([task] { (*task)(); });
    }
    ready_.notify_one();
    return result;
}
void BrokerService::cancel() {
    ++epoch_;
    eraseRequested_ = true;
    ready_.notify_one();
}
bool BrokerService::isCurrentTransportResult(const BrokerResult& result) const {
    return result.ok && result.control.phase == "ACTIVE" && result.operationEpoch == epoch_ &&
           !stopping_;
}
std::future<BrokerResult> BrokerService::importProfile(QJsonObject profile, QByteArray pin,
                                                       QString backup) {
    auto token = ++epoch_;
    auto secret = std::make_shared<Pin>(std::move(pin));
    return enqueue([this, token, profile, secret, backup] {
        need(!store_ && !root_, "CREDENTIAL_ALREADY_OPEN");
        auto current = [this, token] { return epoch_ == token && !stopping_; };
        need(current(), "CREDENTIAL_CANCELLED");
        auto proof =
            RootCodec::openExisting(profile.value("root").toObject(), secret->bytes, current);
        store_ = CredentialStore::importProfile(path_, key_, profile, proof, backup, current);
        auto result = success(store_->read());
        result.committed = true;
        if (current())
            root_ = std::make_unique<PreparedRoot>(std::move(proof));
        else {
            result.ok = false;
            result.code = "CREDENTIAL_CANCELLED";
        }
        return result;
    });
}
std::future<BrokerResult> BrokerService::unlock(QByteArray pin) {
    auto token = ++epoch_;
    auto secret = std::make_shared<Pin>(std::move(pin));
    return enqueue([this, token, secret] {
        root_.reset();
        auto current = [this, token] { return epoch_ == token && !stopping_; };
        need(current(), "CREDENTIAL_CANCELLED");
        if (!store_)
            store_ = CredentialStore::openExisting(path_, key_);
        auto s = store_->read();
        auto opened = RootCodec::openExisting(s.root, secret->bytes, current);
        need(opened.deviceId() == s.deviceId, "CREDENTIAL_BINDING_INVALID");
        need(current(), "CREDENTIAL_CANCELLED");
        root_ = std::make_unique<PreparedRoot>(std::move(opened));
        return success(s);
    });
}
std::future<BrokerResult> BrokerService::change(QByteArray oldPin, QByteArray newPin,
                                                QByteArray wipePin, std::function<bool()> cleanup) {
    auto token = ++epoch_;
    auto old = std::make_shared<Pin>(std::move(oldPin)),
         next = std::make_shared<Pin>(std::move(newPin)),
         wipe = std::make_shared<Pin>(std::move(wipePin));
    return enqueue([this, token, old, next, wipe, cleanup] {
        root_.reset();
        auto current = [this, token] { return epoch_ == token && !stopping_; };
        need(current(), "CREDENTIAL_CANCELLED");
        need(!next->bytes.isEmpty() && next->bytes != wipe->bytes, "PIN_COLLISION");
        need(bool(cleanup), "CREDENTIAL_CLEANUP_ADAPTER_REQUIRED");
        if (!store_)
            store_ = CredentialStore::openExisting(path_, key_);
        auto before = store_->read();
        auto proof = RootCodec::openExisting(before.root, old->bytes, current);
        need(proof.deviceId() == before.deviceId, "CREDENTIAL_BINDING_INVALID");
        auto candidate = RootCodec::prepareRewrap(proof, next->bytes);
        candidate["credentials"] =
            QJsonObject{{"version", 1},
                        {"state", "ready"},
                        {"legacyCleanup", "required"},
                        {"wipe", RootCodec::wipeVerifier(wipe->bytes, current)}};
        candidate["credentialRevision"] = double(before.revision + 1);
        auto verified = RootCodec::openExisting(candidate, next->bytes, current);
        auto committed = store_->commit(before, candidate, verified, true, current);
        BrokerResult result = success(committed);
        result.committed = true;
        // Durable commit cannot be relabelled cancellation/rollback if cleanup fails.
        try {
            need(current(), "CREDENTIAL_CANCELLED");
            need(cleanup(), "MIGRATION_CLEANUP_REQUIRED");
            need(current(), "CREDENTIAL_CANCELLED");
            auto c = committed.root.value("credentials").toObject();
            c["legacyCleanup"] = "complete";
            auto clean = committed.root;
            clean["credentials"] = c;
            auto ready = RootCodec::openExisting(clean, next->bytes, current);
            auto final = store_->commit(committed, clean, ready, false, current);
            result = success(final);
            result.committed = true;
            if (current())
                root_ = std::make_unique<PreparedRoot>(std::move(ready));
            else {
                result.ok = false;
                result.code = "CREDENTIAL_CANCELLED";
            }
        } catch (const Error& e) {
            result.ok = false;
            result.code = QString::fromLatin1(e.what());
        } catch (...) {
            result.ok = false;
            result.code = "MIGRATION_CLEANUP_REQUIRED";
        }
        return result;
    });
}
std::future<BrokerResult> BrokerService::resumeCleanup(QByteArray pin,
                                                       std::function<bool()> cleanup) {
    auto token = ++epoch_;
    auto secret = std::make_shared<Pin>(std::move(pin));
    return enqueue([this, token, secret, cleanup] {
        root_.reset();
        auto current = [this, token] { return epoch_ == token && !stopping_; };
        need(current(), "CREDENTIAL_CANCELLED");
        if (!store_)
            store_ = CredentialStore::openExisting(path_, key_);
        auto before = store_->read();
        auto proof = RootCodec::openExisting(before.root, secret->bytes, current);
        need(proof.deviceId() == before.deviceId, "CREDENTIAL_BINDING_INVALID");
        if (!before.cleanupPending) {
            root_ = std::make_unique<PreparedRoot>(std::move(proof));
            return success(before);
        }
        BrokerResult result = success(before);
        result.committed = true;
        try {
            need(bool(cleanup) && cleanup(), "MIGRATION_CLEANUP_REQUIRED");
            need(current(), "CREDENTIAL_CANCELLED");
            auto candidate = before.root, c = candidate.value("credentials").toObject();
            need(c.value("state") == "ready", "CREDENTIAL_MIGRATION_REQUIRED");
            c["legacyCleanup"] = "complete";
            candidate["credentials"] = c;
            auto ready = RootCodec::openExisting(candidate, secret->bytes, current);
            auto after = store_->commit(before, candidate, ready, false, current);
            result = success(after);
            result.committed = true;
            if (current())
                root_ = std::make_unique<PreparedRoot>(std::move(ready));
            else {
                result.ok = false;
                result.code = "CREDENTIAL_CANCELLED";
            }
        } catch (const Error& e) {
            result.ok = false;
            result.code = QString::fromLatin1(e.what());
        } catch (...) {
            result.ok = false;
            result.code = "MIGRATION_CLEANUP_REQUIRED";
        }
        return result;
    });
}
std::future<BrokerResult> BrokerService::confirmAccountImport(PublishedAccountImport proof) {
    auto token = epoch_.load();
    return enqueue([this, token, proof] {
        auto current = [this, token] { return epoch_ == token && !stopping_; };
        need(current() && bool(root_), "ROOT_UNLOCK_REQUIRED");
        auto snapshot = store_->read();
        need(root_->matchesRecord(snapshot.root), "CREDENTIAL_CONFLICT");
        return success(store_->confirmAccountImport(proof, current));
    });
}
std::future<BrokerResult> BrokerService::accountImportInventory() {
    auto token = epoch_.load();
    return enqueue([this, token] {
        need(token == epoch_ && bool(root_), "ROOT_UNLOCK_REQUIRED");
        auto snapshot = store_->read();
        need(root_->matchesRecord(snapshot.root), "CREDENTIAL_CONFLICT");
        need(snapshot.accountImportPhase == "PENDING", snapshot.accountImportPhase == "COMMITTED"
                                                           ? "ACCOUNT_IMPORT_ALREADY_COMMITTED"
                                                           : "ACCOUNT_IMPORT_RECOVERY_UNVERIFIED");
        BrokerResult result = success(snapshot);
        result.profileInventory = store_->exportOriginalProfile();
        need(token == epoch_, "CREDENTIAL_CANCELLED");
        return result;
    });
}
std::future<BrokerResult> BrokerService::readAccountRegistry(QJsonArray rows) {
    auto token = epoch_.load();
    return enqueue([this, token, rows] {
        need(token == epoch_ && bool(root_), "ROOT_UNLOCK_REQUIRED");
        auto snapshot = store_->read();
        need(root_->matchesRecord(snapshot.root), "CREDENTIAL_CONFLICT");
        BrokerResult result = success(snapshot);
        result.accountRegistry = RootCodec::readAccountRegistry(*root_, rows);
        need(token == epoch_, "CREDENTIAL_CANCELLED");
        return result;
    });
}
std::future<BrokerResult> BrokerService::enableNode(RootCodec::NodeSeedFactory factory) {
    const auto token = epoch_.load();
    return enqueue([this, token, factory] {
        auto current = [this, token] { return token == epoch_ && !stopping_; };
        need(current() && bool(root_), "ROOT_UNLOCK_REQUIRED");
        auto before = store_->read();
        need(root_->matchesRecord(before.root), "CREDENTIAL_CONFLICT");
        auto candidate = RootCodec::prepareNodeEnable(*root_, factory);
        if (before.root.contains("credentialRevision"))
            candidate.second["credentialRevision"] = before.root.value("credentialRevision");
        if (candidate.second == before.root)
            return success(before);
        auto after = store_->commitNodeEnable(before, candidate.second, candidate.first, current);
        auto result = success(after);
        result.committed = true;
        root_ = std::make_unique<PreparedRoot>(std::move(candidate.first));
        if (!current()) {
            root_.reset();
            result.ok = false;
            result.code = "CREDENTIAL_CANCELLED";
        }
        return result;
    });
}
std::future<BrokerResult> BrokerService::transport(QJsonArray endpoints, bool direct) {
    auto token = epoch_.load();
    return enqueue([this, token, endpoints, direct] {
        need(token == epoch_ && bool(root_), "CREDENTIAL_CANCELLED");
        auto s = store_->read();
        need(root_->matchesRecord(s.root), "CREDENTIAL_CONFLICT");
        // Validate material and migration state before burning a durable reservation.
        auto bundle = RootCodec::existingTransportBundle(*root_, endpoints, 1, direct);
        if (!control_) {
            if (QFileInfo::exists(controlPath_))
                control_ = ControlJournal::openExisting(controlPath_, root_->deviceId());
            else
                control_ = ControlJournal::createForProfile(controlPath_, *root_);
        }
        auto state = control_->reserveSession(*root_);
        BrokerResult result = success(s);
        result.control = state;
        result.operationEpoch = token;
        if (token != epoch_) {
            result.ok = false;
            result.code = "CREDENTIAL_CANCELLED";
            result.control = control_->beginFullLock();
            return result;
        }
        bundle["generation"] = double(state.generation);
        result.transportBundle = std::move(bundle);
        return result;
    });
}
std::future<BrokerResult> BrokerService::fullRootLock() {
    cancel();
    return enqueue([this] {
        root_.reset();
        BrokerResult r;
        r.ok = true;
        if (!control_ && QFileInfo::exists(controlPath_)) {
            if (!store_)
                store_ = CredentialStore::openExisting(path_, key_);
            control_ = ControlJournal::openExisting(controlPath_, store_->read().deviceId);
        }
        if (control_)
            r.control = control_->beginFullLock();
        return r;
    });
}
std::future<BrokerResult> BrokerService::confirmTransportStopped(ControlState pending) {
    return enqueue([this, pending] {
        need(bool(control_), "CONTROL_STORE_MISSING");
        BrokerResult r;
        r.ok = true;
        r.control = control_->confirmStopped(pending);
        return r;
    });
}
std::future<BrokerResult>
BrokerService::mergeStoppedDaemonFloors(ControlState expected, quint64 generation, quint64 policy) {
    return enqueue([this, expected, generation, policy] {
        need(bool(control_), "CONTROL_STORE_MISSING");
        BrokerResult result;
        result.ok = true;
        result.control = control_->mergeStoppedDaemonFloors(expected, generation, policy);
        return result;
    });
}
} // namespace dmash::broker

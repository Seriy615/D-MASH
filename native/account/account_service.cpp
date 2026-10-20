#include "account_service.h"
#include "../src/crypto_port.h"
#include "account_sql_store.h"
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QFile>
#include <QHash>
#include <QJsonDocument>
#include <QResource>
#include <QStringConverter>
#include <QUrl>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <limits>
#include <mutex>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <thread>
extern "C" {
#include "quickjs.h"
}
static void initAccountResources() {
    Q_INIT_RESOURCE(dmash_account_modules);
    Q_INIT_RESOURCE(dmash_account_platform);
    Q_INIT_RESOURCE(dmash_account_entry);
}
namespace dmash::account {
namespace {
void need(bool b, const char *c = "ACCOUNT_ADAPTER_FAILED") {
    if (!b)
        throw AccountError(c);
}
QString text(JSContext *c, JSValueConst v, int cap = 2 * 1024 * 1024) {
    need(JS_IsString(v));
    size_t n = 0;
    const char *p = JS_ToCStringLen(c, &n, v);
    need(p);
    if (n > size_t(cap)) {
        JS_FreeCString(c, p);
        throw AccountError("ACCOUNT_INPUT_LIMIT");
    }
    auto out = QString::fromUtf8(p, qsizetype(n));
    JS_FreeCString(c, p);
    return out;
}
QByteArray bytes(JSContext *c, JSValueConst v) {
    size_t offset = 0, len = 0, bpe = 0, total = 0;
    JSValue b = JS_GetTypedArrayBuffer(c, v, &offset, &len, &bpe);
    need(!JS_IsException(b));
    auto *p = JS_GetArrayBuffer(c, &total, b);
    if ((!p && total != 0) || offset > total || len > total - offset || len > 2 * 1024 * 1024) {
        JS_FreeValue(c, b);
        throw AccountError("ACCOUNT_INPUT_LIMIT");
    }
    QByteArray out(reinterpret_cast<char *>(p ? p + offset : nullptr), qsizetype(len));
    JS_FreeValue(c, b);
    return out;
}
JSValue buffer(JSContext *c, QByteArray b, bool typed = false) {
    auto v = JS_NewArrayBufferCopy(c, reinterpret_cast<const uint8_t *>(b.constData()),
                                   size_t(b.size()));
    OPENSSL_cleanse(b.data(), b.size());
    if (!typed || JS_IsException(v))
        return v;
    JSValue args[] = {v, JS_UNDEFINED, JS_UNDEFINED};
    auto out = JS_NewTypedArray(c, 3, args, JS_TYPED_ARRAY_UINT8);
    JS_FreeValue(c, v);
    return out;
}
void put(JSContext *c, JSValue o, const char *k, JSValue v) {
    need(JS_SetPropertyStr(c, o, k, v) >= 0);
}
JSValue json(JSContext *c, const QJsonValue &v) {
    auto b = QJsonDocument(QJsonArray{v}).toJson(QJsonDocument::Compact);
    auto a = JS_ParseJSON(c, b.constData(), size_t(b.size()), "account-port");
    need(!JS_IsException(a));
    auto result = JS_GetPropertyUint32(c, a, 0);
    JS_FreeValue(c, a);
    return result;
}
QJsonValue jsonValue(JSContext *c, JSValueConst v) {
    auto s = JS_JSONStringify(c, v, JS_UNDEFINED, JS_UNDEFINED);
    need(!JS_IsException(s) && JS_IsString(s));
    auto b = text(c, s, 64 * 1024 * 1024).toUtf8();
    JS_FreeValue(c, s);
    QJsonParseError error;
    auto doc = QJsonDocument::fromJson("[" + b + "]", &error);
    need(error.error == QJsonParseError::NoError && doc.isArray());
    return doc.array()[0];
}
struct Key {
    SecretBytes secret;
    QString algorithm, usages;
    Key(QByteArray b, QString a, QString u)
        : secret(std::move(b)), algorithm(std::move(a)), usages(std::move(u)) {}
};
JSClassID keyClass;
std::once_flag keyOnce, resourceOnce;
void finalizeKey(JSRuntime *, JSValue v) { delete static_cast<Key *>(JS_GetOpaque(v, keyClass)); }
Key *key(JSContext *c, JSValueConst v, const QString &a, const QString &usage) {
    auto *k = static_cast<Key *>(JS_GetOpaque2(c, v, keyClass));
    need(k && k->algorithm == a && k->usages.split(',').contains(usage), "ACCOUNT_KEY_SCOPE");
    return k;
}
QByteArray accountKdf(const QByteArray &password, const QByteArray &salt) {
    need(!password.isEmpty() && password.size() <= 4096 && !salt.isEmpty() && salt.size() <= 4096,
         "ACCOUNT_CREDENTIAL_REQUIRED");
    uint32_t lanes = 1, threads = 1, iter = 3, mem = 65536, version = 19;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD, const_cast<char *>(password.constData()), password.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<char *>(salt.constData()),
                                          salt.size()),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version),
        OSSL_PARAM_END};
    EVP_KDF *k = EVP_KDF_fetch(nullptr, "ARGON2D", nullptr);
    need(k, "ACCOUNT_KDF_UNAVAILABLE");
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(k);
    EVP_KDF_free(k);
    need(c);
    QByteArray out(128, Qt::Uninitialized);
    const bool ok =
        EVP_KDF_derive(c, reinterpret_cast<unsigned char *>(out.data()), 128, params) == 1;
    EVP_KDF_CTX_free(c);
    if (!ok) {
        OPENSSL_cleanse(out.data(), out.size());
        throw AccountError("ACCOUNT_KDF_FAILED");
    }
    return out;
}
} // namespace
struct AccountService::State {
    QString path;
    Transport transport;
    RegistryReader registryReader;
    std::atomic<quint64> epoch{1};
    std::atomic<bool> stopping{false};
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<std::function<void()>> queue;
    std::thread worker;
    JSRuntime *rt = nullptr;
    JSContext *ctx = nullptr;
    std::unique_ptr<AccountSqlStore> store;
    QElapsedTimer clock;
    QHash<int, qint64> timers;
    State(QString p, Transport t, RegistryReader r)
        : path(std::move(p)), transport(std::move(t)), registryReader(std::move(r)) {
        worker = std::thread([this] {
            clock.start();
            for (;;) {
                std::function<void()> f;
                {
                    std::unique_lock<std::mutex> l(mutex);
                    if (timers.isEmpty()) {
                        ready.wait(l, [this] { return stopping || !queue.empty(); });
                    } else {
                        qint64 deadline = std::numeric_limits<qint64>::max();
                        for (auto value : timers)
                            deadline = std::min(deadline, value);
                        ready.wait_for(l,
                                       std::chrono::milliseconds(
                                           std::max<qint64>(0, deadline - clock.elapsed())),
                                       [this] { return stopping || !queue.empty(); });
                    }
                    if (queue.empty() && stopping)
                        break;
                    if (!queue.empty()) {
                        f = std::move(queue.front());
                        queue.pop_front();
                    }
                }
                if (f)
                    f();
                if (ctx && !stopping)
                    tick();
            }
            shutdown();
            store.reset();
        });
    }
    ~State() {
        ++epoch;
        stopping = true;
        ready.notify_all();
        worker.join();
    }
    std::future<AccountResult> enqueue(std::function<AccountResult()> f) {
        auto task = std::make_shared<std::packaged_task<AccountResult()>>([f = std::move(f)] {
            try {
                return f();
            } catch (const AccountError &e) {
                AccountResult r;
                r.code = QString::fromLatin1(e.what());
                return r;
            } catch (...) {
                AccountResult r;
                r.code = "ACCOUNT_ADAPTER_FAILED";
                return r;
            }
        });
        auto result = task->get_future();
        {
            std::lock_guard<std::mutex> l(mutex);
            if (stopping || queue.size() >= 16) {
                std::promise<AccountResult> p;
                AccountResult r;
                r.code = "ACCOUNT_BUSY";
                p.set_value(r);
                return p.get_future();
            }
            queue.push_back([task] { (*task)(); });
        }
        ready.notify_one();
        return result;
    }
    void shutdown() {
        if (ctx) {
            try {
                invoke("logout");
            } catch (...) {
            }
            JS_RunGC(rt);
        }
        timers.clear();
        if (ctx) {
            JS_FreeContext(ctx);
            ctx = nullptr;
        }
        if (rt) {
            JS_FreeRuntime(rt);
            rt = nullptr;
        }
        if (store)
            store->abort();
    }
    void load(const QString &name) {
        QFile f(":/dmash/account/" + name);
        need(f.open(QIODevice::ReadOnly) && f.size() <= 2 * 1024 * 1024, "ACCOUNT_MODULE_MISSING");
        auto source = f.readAll();
        auto v = JS_Eval(ctx, source.constData(), size_t(source.size()), name.toUtf8().constData(),
                         JS_EVAL_TYPE_GLOBAL);
        if (JS_IsException(v)) {
            JS_FreeValue(ctx, JS_GetException(ctx));
            throw AccountError("ACCOUNT_MODULE_FAILED");
        }
        JS_FreeValue(ctx, v);
    }
    void initialize() {
        if (ctx)
            return;
        if (!store)
            store = AccountSqlStore::openExisting(path);
        std::call_once(resourceOnce, initAccountResources);
        rt = JS_NewRuntime();
        need(rt);
        JS_SetMemoryLimit(rt, 128 * 1024 * 1024);
        JS_SetMaxStackSize(rt, 2 * 1024 * 1024);
        ctx = JS_NewContext(rt);
        need(ctx);
        JS_SetContextOpaque(ctx, this);
        std::call_once(keyOnce, [] { JS_NewClassID(&keyClass); });
        JSClassDef def{};
        def.class_name = "NativeAccountCryptoKey";
        def.finalizer = finalizeKey;
        need(JS_NewClass(rt, keyClass, &def) == 0);
        auto global = JS_GetGlobalObject(ctx);
        put(ctx, global, "__dmashHost", JS_NewCFunction(ctx, host, "__dmashHost", 1));
        JS_FreeValue(ctx, global);
        load("native/platform.js");
        const char setup[] =
            "globalThis.window=globalThis;globalThis.document={getElementById:()=>null};";
        auto v = JS_Eval(ctx, setup, sizeof(setup) - 1, "account-environment", JS_EVAL_TYPE_GLOBAL);
        need(!JS_IsException(v));
        JS_FreeValue(ctx, v);
        const QStringList modules = {"vendor/nacl-fast.min.js",
                                     "secure_session.js",
                                     "route_discovery_v4.js",
                                     "recipient_payload_v4.js",
                                     "account_pairing_v2.js",
                                     "account_route_binding_v2.js",
                                     "account_route_journal_v2.js",
                                     "account_sealed_operation_v4.js",
                                     "account_handshake_v4.js",
                                     "account_session_v4.js",
                                     "account_session_store_v4.js",
                                     "account_app_cipher_v4.js",
                                     "account_app_outbox_v4.js",
                                     "account_authenticated_history_v4.js",
                                     "account_session_runtime_v4.js",
                                     "account_static_kem_v1.js",
                                     "storage.js",
                                     "saved_messages.js",
                                     "native/idb.js",
                                     "native/account_entry.js"};
        for (auto name : modules)
            load(name);
    }
    void drain() {
        for (int i = 0; i < 100000; ++i) {
            JSContext *job = nullptr;
            int n = JS_ExecutePendingJob(rt, &job);
            if (n < 0) {
                JS_FreeValue(job, JS_GetException(job));
                throw AccountError("ACCOUNT_JS_JOB_FAILED");
            }
            if (!n)
                return;
        }
        throw AccountError("ACCOUNT_JOB_LIMIT");
    }
    AccountResult invoke(const char *method, const QJsonObject &params = {}) {
        initialize();
        auto global = JS_GetGlobalObject(ctx),
             object = JS_GetPropertyStr(ctx, global, "NativeAccount"),
             fn = JS_GetPropertyStr(ctx, object, method), argument = json(ctx, params);
        auto result = JS_Call(ctx, fn, object, 1, &argument);
        JS_FreeValue(ctx, argument);
        JS_FreeValue(ctx, fn);
        JS_FreeValue(ctx, object);
        JS_FreeValue(ctx, global);
        AccountResult out;
        if (JS_IsException(result)) {
            auto e = JS_GetException(ctx);
            auto code = JS_GetPropertyStr(ctx, e, "code");
            out.code = JS_IsString(code) ? text(ctx, code, 256) : "ACCOUNT_JS_FAILED";
            JS_FreeValue(ctx, code);
            JS_FreeValue(ctx, e);
            JS_FreeValue(ctx, result);
            return out;
        }
        try {
            drain();
            auto state = JS_PromiseState(ctx, result);
            if (state == JS_PROMISE_PENDING)
                throw AccountError("ACCOUNT_ASYNC_INCOMPLETE");
            auto value = state == JS_PROMISE_FULFILLED || state == JS_PROMISE_REJECTED
                             ? JS_PromiseResult(ctx, result)
                             : JS_DupValue(ctx, result);
            if (state == JS_PROMISE_REJECTED) {
                auto code = JS_GetPropertyStr(ctx, value, "code");
                out.code = JS_IsString(code) ? text(ctx, code, 256) : "ACCOUNT_JS_FAILED";
                JS_FreeValue(ctx, code);
            } else {
                auto v = jsonValue(ctx, value);
                out.ok = true;
                if (v.isArray())
                    out.rows = v.toArray();
                else if (v.isObject())
                    out.value = v.toObject();
            }
            JS_FreeValue(ctx, value);
            JS_FreeValue(ctx, result);
            return out;
        } catch (...) {
            JS_FreeValue(ctx, result);
            throw;
        }
    }
    void tick() {
        auto due = timers.keys();
        for (int id : due)
            if (timers.contains(id) && timers[id] <= clock.elapsed()) {
                timers.remove(id);
                auto global = JS_GetGlobalObject(ctx),
                     fn = JS_GetPropertyStr(ctx, global, "__nativeEvent");
                JSValue args[] = {JS_NewString(ctx, "timer"), JS_NewInt32(ctx, id), JS_UNDEFINED};
                auto v = JS_Call(ctx, fn, global, 3, args);
                for (auto a : args)
                    JS_FreeValue(ctx, a);
                JS_FreeValue(ctx, fn);
                JS_FreeValue(ctx, global);
                if (JS_IsException(v))
                    JS_FreeValue(ctx, JS_GetException(ctx));
                JS_FreeValue(ctx, v);
                try {
                    drain();
                } catch (...) { /* Durable intents remain in SQLite for the next authenticated
                                   session. */
                }
            }
    }
    static JSValue host(JSContext *c, JSValueConst, int argc, JSValueConst *argv) {
        auto *self = static_cast<State *>(JS_GetContextOpaque(c));
        try {
            need(argc >= 1);
            auto op = text(c, argv[0], 64);
            auto arg = [&](int i) {
                need(i < argc);
                return argv[i];
            };
            auto number = [&](int i) {
                int32_t n = 0;
                need(JS_ToInt32(c, &n, arg(i)) == 0);
                return n;
            };
            auto string = [&](int i) { return text(c, arg(i)); };
            if (op == "isWorker" || op == "benchmarkEnabled")
                return JS_FALSE;
            if (op == "epoch")
                return JS_NewInt64(c, self->epoch);
            if (op == "monotonic")
                return JS_NewFloat64(c, double(self->clock.elapsed()));
            if (op == "timerStart") {
                need(self->timers.size() < 1024, "ACCOUNT_TIMER_LIMIT");
                self->timers[number(1)] = self->clock.elapsed() + number(2);
                return JS_UNDEFINED;
            }
            if (op == "timerStop") {
                self->timers.remove(number(1));
                return JS_UNDEFINED;
            }
            if (op == "utf8Encode")
                return buffer(c, string(1).toUtf8());
            if (op == "utf8Decode") {
                auto b = bytes(c, arg(1));
                QStringDecoder decoder(QStringDecoder::Utf8, QStringConverter::Flag::Stateless);
                const QString s = decoder(b);
                need(JS_ToBool(c, arg(2)) != 1 || !decoder.hasError(), "ACCOUNT_UTF8_INVALID");
                auto encoded = s.toUtf8();
                return JS_NewStringLen(c, encoded.constData(), size_t(encoded.size()));
            }
            if (op == "base64Encode")
                return JS_NewString(c, bytes(c, arg(1)).toBase64().constData());
            if (op == "base64Decode") {
                auto b = QByteArray::fromBase64Encoding(string(1).toLatin1(),
                                                        QByteArray::AbortOnBase64DecodingErrors);
                need(bool(b), "ACCOUNT_BASE64_INVALID");
                auto s = QString::fromLatin1(b.decoded).toUtf8();
                return JS_NewStringLen(c, s.constData(), size_t(s.size()));
            }
            if (op == "randomFill") {
                size_t o = 0, n = 0, bpe = 0, total = 0;
                auto b = JS_GetTypedArrayBuffer(c, arg(1), &o, &n, &bpe);
                need(!JS_IsException(b) && n <= 65536);
                auto *p = JS_GetArrayBuffer(c, &total, b);
                need(p && o + n <= total);
                auto random = CryptoPort::random(int(n));
                memcpy(p + o, random.constData(), n);
                OPENSSL_cleanse(random.data(), random.size());
                JS_FreeValue(c, b);
                return JS_UNDEFINED;
            }
            if (op == "keyImport") {
                auto b = bytes(c, arg(1));
                auto a = string(2), u = string(3);
                need((a == "AES-GCM" && b.size() == 32) || (a == "HMAC" && !b.isEmpty()) ||
                         (a == "HKDF" && !b.isEmpty()),
                     "ACCOUNT_KEY_INVALID");
                auto v = JS_NewObjectClass(c, keyClass);
                need(!JS_IsException(v));
                JS_SetOpaque(v, new Key(std::move(b), a, u));
                return v;
            }
            if (op == "sha256")
                return buffer(c, CryptoPort::sha256(bytes(c, arg(1))));
            if (op == "hmac")
                return buffer(c,
                              CryptoPort::hmacSha256(key(c, arg(1), "HMAC", "sign")->secret.bytes(),
                                                     bytes(c, arg(2))));
            if (op == "hmacVerify") {
                auto signature = bytes(c, arg(2)),
                     expected = CryptoPort::hmacSha256(
                         key(c, arg(1), "HMAC", "verify")->secret.bytes(), bytes(c, arg(3)));
                return JS_NewBool(c, signature.size() == expected.size() &&
                                         CRYPTO_memcmp(signature.constData(), expected.constData(),
                                                       signature.size()) == 0);
            }
            if (op == "hkdf" || op == "hkdfKey")
                return buffer(
                    c, CryptoPort::hkdfSha256(key(c, arg(1), "HKDF", op == "hkdfKey" ? "deriveKey" : "deriveBits")->secret.bytes(),
                                              bytes(c, arg(2)), bytes(c, arg(3)), number(4)));
            if (op == "encrypt" || op == "decrypt")
                return buffer(c,
                              CryptoPort::aesGcm(
                                  op == "encrypt",
                                  key(c, arg(1), "AES-GCM", op == "encrypt" ? "encrypt" : "decrypt")
                                      ->secret.bytes(),
                                  bytes(c, arg(2)), bytes(c, arg(3)), bytes(c, arg(4)), number(5)));
            if (op == "accountKdf") {
                SecretBytes password(string(2).toUtf8());
                return buffer(
                    c, accountKdf(password.bytes(), string(1).toUtf8() + "D_MASH_GAMMA_V1_STABLE"),
                    true);
            }
            if (op == "kemKeypair") {
                auto k = LegacyKyber::generateKeys();
                auto v = JS_NewObject(c);
                put(c, v, "pk", buffer(c, k.publicKey, true));
                put(c, v, "sk", buffer(c, k.secretKey.bytes(), true));
                return v;
            }
            if (op == "kemEncapsulate") {
                auto k = LegacyKyber::encapsulate(bytes(c, arg(1)));
                auto v = JS_NewObject(c);
                put(c, v, "ct", buffer(c, k.ciphertext, true));
                put(c, v, "ss", buffer(c, k.secret.bytes(), true));
                return v;
            }
            if (op == "kemDecapsulate") {
                SecretBytes sk(bytes(c, arg(2)));
                auto k = LegacyKyber::decapsulate(bytes(c, arg(1)), sk.bytes());
                return buffer(c, k.bytes(), true);
            }
            if (op == "hasSecureRegistry")
                return JS_NewBool(c, self->store->secureRegistry());
            if (op == "registryRead") {
                need(bool(self->registryReader), "ROOT_UNLOCK_REQUIRED");
                return json(c, self->registryReader(jsonValue(c, arg(1)).toArray()));
            }
            if (op == "idbStores")
                return json(c, self->store->stores(string(1)));
            if (op == "idbBegin") {
                QStringList names;
                for (auto n : jsonValue(c, arg(2)).toArray())
                    names.append(n.toString());
                self->store->begin(string(1), names, JS_ToBool(c, arg(3)) == 1);
                return JS_UNDEFINED;
            }
            if (op == "idbGet")
                return json(c, self->store->get(string(1), jsonValue(c, arg(2))));
            if (op == "idbGetAll")
                return json(c, self->store->getAll(string(1)));
            if (op == "idbPut") {
                self->store->put(string(1), jsonValue(c, arg(2)), jsonValue(c, arg(3)).toObject());
                return JS_UNDEFINED;
            }
            if (op == "idbDelete") {
                self->store->remove(string(1), jsonValue(c, arg(2)));
                return JS_UNDEFINED;
            }
            if (op == "idbCommit") {
                self->store->commit();
                return JS_UNDEFINED;
            }
            if (op == "idbAbort") {
                self->store->abort();
                return JS_UNDEFINED;
            }
            if (op == "transport") {
                need(bool(self->transport), "ACCOUNT_TRANSPORT_UNAVAILABLE");
                return json(c,
                            self->transport(string(1), string(2), jsonValue(c, arg(3)).toObject()));
            }
            throw AccountError("ACCOUNT_HOST_OPERATION_REJECTED");
        } catch (const std::exception &e) {
            auto error = JS_NewError(c);
            put(c, error, "code", JS_NewString(c, e.what()));
            put(c, error, "message", JS_NewString(c, e.what()));
            return JS_Throw(c, error);
        }
    }
};
AccountService::AccountService(QString path, Transport transport, RegistryReader reader)
    : state_(std::make_unique<State>(std::move(path), std::move(transport), std::move(reader))) {}
AccountService::~AccountService() = default;
std::future<AccountResult> AccountService::importProfile(QJsonObject p) {
    const auto token = state_->epoch.load();
    return state_->enqueue([s = state_.get(), p, token] {
        need(s->epoch == token, "ACCOUNT_SESSION_CHANGED");
        if (s->store) {
            const auto bytes = QJsonDocument(p).toJson(QJsonDocument::Compact);
            const auto digest = QString::fromLatin1(
                QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
            need(s->store->sourceDigest() == digest, "ACCOUNT_PROFILE_CONFLICT");
        } else {
            need(!s->ctx, "ACCOUNT_ALREADY_OPEN");
            s->store = AccountSqlStore::importProfile(s->path, p);
        }
        AccountResult r;
        r.ok = true;
        r.value = {{"imported", true}};
        r.importProof = s->store->publishedImportProof();
        if (s->epoch != token) {
            r.ok = false;
            r.code = "ACCOUNT_SESSION_CHANGED";
        }
        return r;
    });
}
std::future<AccountResult> AccountService::verifyPublishedImport() {
    return state_->enqueue([s = state_.get()] {
        if (!s->store)
            s->store = AccountSqlStore::openExisting(s->path);
        AccountResult result;
        result.ok = true;
        result.importProof = s->store->publishedImportProof();
        return result;
    });
}
std::future<AccountResult> AccountService::listAccounts() {
    return state_->enqueue([s = state_.get()] { return s->invoke("listAccounts"); });
}
std::future<AccountResult> AccountService::login(QString identity, QByteArray password) {
    auto secret = std::make_shared<SecretBytes>(std::move(password));
    auto token = ++state_->epoch;
    return state_->enqueue([s = state_.get(), identity, secret, token] {
        need(s->epoch == token, "ACCOUNT_SESSION_CHANGED");
        return s->invoke(
            "login", {{"identity", identity}, {"password", QString::fromUtf8(secret->bytes())}});
    });
}
std::future<AccountResult> AccountService::sync() {
    return state_->enqueue([s = state_.get()] { return s->invoke("sync"); });
}
std::future<AccountResult> AccountService::listContacts() {
    return state_->enqueue([s = state_.get()] { return s->invoke("listContacts"); });
}
std::future<AccountResult> AccountService::listHistory(QString peer, int before, int limit) {
    return state_->enqueue([s = state_.get(), peer, before, limit] {
        return s->invoke("listHistory", {{"peer", peer}, {"before", before}, {"limit", limit}});
    });
}
std::future<AccountResult> AccountService::sendText(QString peer, QString operation, QString text) {
    return state_->enqueue([s = state_.get(), peer, operation, text] {
        return s->invoke("sendText", {{"peer", peer}, {"operationId", operation}, {"text", text}});
    });
}
std::future<AccountResult> AccountService::logout() {
    ++state_->epoch;
    return state_->enqueue([s = state_.get()] { return s->invoke("logout"); });
}
void AccountService::cancel() {
    ++state_->epoch;
    state_->enqueue([s = state_.get()] {
        if (s->ctx)
            return s->invoke("logout");
        AccountResult r;
        r.ok = true;
        return r;
    });
}
} // namespace dmash::account

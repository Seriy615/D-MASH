#include "js_actor.h"
#include "crypto_port.h"
#ifdef Q_OS_WIN
#include "os_windows.h"
#endif
#include "inbox_sql_store.h"
#include "job_ledger.h"
#include "nonce_hash.h"
#include "storage_port.h"
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLockFile>
#include <QPointer>
#include <QResource>
#include <QSet>
#include <QSslSocket>
#include <QStringConverter>
#include <QThread>
#include <QTimer>
#include <QWebSocket>
#include <atomic>
#include <cstring>
#include <mutex>
#include <openssl/crypto.h>
#include <stdexcept>
#ifdef Q_OS_UNIX
#include <unistd.h>
#endif
extern "C" {
#include "quickjs.h"
}
static std::once_flag compiledResourceOnce;
static void initCompiledResources() {
    Q_INIT_RESOURCE(dmash_protocol);
    Q_INIT_RESOURCE(dmash_platform);
}
namespace dmash {
namespace {
constexpr int MaxFrame = 2 * 1024 * 1024, MaxClone = 256 * 1024;
void demand(bool ok) {
    if (!ok)
        throw std::runtime_error("Native actor operation rejected");
}
JSClassID keyClass, nonceClass;
std::once_flag keyClassOnce;
struct KeyBudget {
    qsizetype bytes = 0;
    int count = 0;
};
struct NativeNonce {
    NonceHash hash;
    std::shared_ptr<KeyBudget> budget;
    NativeNonce(const QByteArray& prefix, std::shared_ptr<KeyBudget> b)
        : hash(prefix), budget(std::move(b)) {
        ++budget->count;
    }
    ~NativeNonce() { --budget->count; }
};
void nonceFinalizer(JSRuntime*, JSValue value) {
    delete static_cast<NativeNonce*>(JS_GetOpaque(value, nonceClass));
}
struct WipeBytes {
    QByteArray& value;
    ~WipeBytes() {
        if (!value.isEmpty())
            OPENSSL_cleanse(value.data(), size_t(value.size()));
    }
};
struct NativeKey {
    QByteArray bytes;
    QString algorithm, usages;
    std::shared_ptr<KeyBudget> budget;
    ~NativeKey() {
        if (budget) {
            budget->bytes -= bytes.size();
            --budget->count;
        }
        if (!bytes.isEmpty())
            OPENSSL_cleanse(bytes.data(), size_t(bytes.size()));
    }
};
void keyFinalizer(JSRuntime*, JSValue value) {
    delete static_cast<NativeKey*>(JS_GetOpaque(value, keyClass));
}
QString string(JSContext* c, JSValueConst value, int cap = MaxFrame) {
    demand(JS_IsString(value));
    size_t n = 0;
    const char* p = JS_ToCStringLen(c, &n, value);
    demand(p != nullptr);
    if (n > size_t(cap)) {
        JS_FreeCString(c, p);
        throw std::runtime_error("Native string limit");
    }
    const auto out = QString::fromUtf8(p, qsizetype(n));
    JS_FreeCString(c, p);
    return out;
}
int integer(JSContext* c, JSValueConst value, int minimum = 0, int maximum = 2147483647) {
    double n = 0;
    demand(JS_IsNumber(value) && JS_ToFloat64(c, &n, value) == 0 && n >= minimum && n <= maximum &&
           n == int(n));
    return int(n);
}
QByteArray bytes(JSContext* c, JSValueConst value, int cap = MaxFrame) {
    size_t offset = 0, len = 0, bpe = 0, total = 0;
    JSValue buffer = JS_GetTypedArrayBuffer(c, value, &offset, &len, &bpe);
    demand(!JS_IsException(buffer));
    auto* p = JS_GetArrayBuffer(c, &total, buffer);
    const bool valid =
        (p || total == 0) && offset <= total && len <= total - offset && len <= size_t(cap);
    if (!valid) {
        JS_FreeValue(c, buffer);
        throw std::runtime_error("Native buffer limit");
    }
    QByteArray out(reinterpret_cast<char*>(p ? p + offset : nullptr), qsizetype(len));
    JS_FreeValue(c, buffer);
    return out;
}
JSValue arrayBuffer(JSContext* c, QByteArray out) {
    JSValue v = JS_NewArrayBufferCopy(c, reinterpret_cast<const uint8_t*>(out.constData()),
                                      size_t(out.size()));
    if (!out.isEmpty())
        OPENSSL_cleanse(out.data(), size_t(out.size()));
    return v;
}
JSValue uint8(JSContext* c, const QByteArray& out) {
    JSValue buffer = JS_NewArrayBufferCopy(c, reinterpret_cast<const uint8_t*>(out.constData()),
                                           size_t(out.size()));
    if (JS_IsException(buffer))
        return buffer;
    // This upstream C API forwards its argv directly to the constructor;
    // provide explicit offset/length slots rather than reading past one value.
    JSValue args[] = {buffer, JS_UNDEFINED, JS_UNDEFINED};
    JSValue result = JS_NewTypedArray(c, 3, args, JS_TYPED_ARRAY_UINT8);
    JS_FreeValue(c, buffer);
    return result;
}
void put(JSContext* c, JSValue object, const char* name, JSValue value) {
    demand(JS_SetPropertyStr(c, object, name, value) >= 0);
}
NativeKey* key(JSContext* c, JSValueConst value, const QString& algorithm, const QString& usage) {
    auto* k = static_cast<NativeKey*>(JS_GetOpaque2(c, value, keyClass));
    demand(k && k->algorithm == algorithm && k->usages.split(',').contains(usage));
    return k;
}
std::atomic_int activeComputes{0};
class Engine;
struct Compute {
    QThread* thread = nullptr;
    QObject* context = nullptr;
    Engine* engine = nullptr;
    std::shared_ptr<std::atomic_bool> cancel = std::make_shared<std::atomic_bool>(false);
    QStringList pending;
    bool closed = false;
};
class Engine final : public QObject {
  public:
    JSRuntime* rt = nullptr;
    JSContext* ctx = nullptr;
    bool closed = false, worker = false;
    std::shared_ptr<std::atomic_bool> cancel;
    QElapsedTimer clock;
    QHash<int, QTimer*> timers;
    QHash<int, QWebSocket*> sockets;
    QHash<int, std::shared_ptr<Compute>> computes;
    std::unique_ptr<RelationshipSqlStore> relations;
    std::unique_ptr<InboxSqlStore> inbox;
    std::unique_ptr<JobLedger> jobs;
    QString profilePath;
    std::function<void(const QString&, const QJsonObject&)> localReply;
    std::function<void(const QJsonObject&)> bootstrapFloors;
    struct BatchGuard {
        QString id;
        QVector<QPair<QString, QString>> jobs;
    };
    QHash<int, BatchGuard> batchGuards;
    std::function<void(const QJsonObject&)> report;
    std::function<void(const QString&)> reply;
    QSet<QString> loaded;
    QJsonObject sourceHashes;
    int nextSocket = 0, nextWorker = 0;
    bool drainQueued = false;
    std::shared_ptr<KeyBudget> keyBudget = std::make_shared<KeyBudget>();
    int clockCalls = 0;
    double firstClock = 0;
    explicit Engine(const QString& profile, const QString& target,
                    std::shared_ptr<std::atomic_bool> cancelFlag, QObject* parent = nullptr)
        : QObject(parent), worker(!target.isEmpty()), cancel(std::move(cancelFlag)) {
        std::call_once(compiledResourceOnce, initCompiledResources);
        try {
            profilePath = profile;
            clock.start();
            rt = JS_NewRuntime();
            demand(rt);
            JS_SetMemoryLimit(rt, 128 * 1024 * 1024);
            JS_SetMaxStackSize(rt, 2 * 1024 * 1024);
            JS_SetInterruptHandler(
                rt,
                [](JSRuntime*, void* ptr) {
                    return static_cast<Engine*>(ptr)->cancel->load() ? 1 : 0;
                },
                this);
            ctx = JS_NewContext(rt);
            demand(ctx);
            JS_SetContextOpaque(ctx, this);
            std::call_once(keyClassOnce, [] {
                JS_NewClassID(&keyClass);
                JS_NewClassID(&nonceClass);
            });
            JSClassDef def{};
            def.class_name = "NativeTransportKey";
            def.finalizer = keyFinalizer;
            demand(JS_NewClass(rt, keyClass, &def) == 0);
            JSClassDef nonceDef{};
            nonceDef.class_name = "NativeNonceHasher";
            nonceDef.finalizer = nonceFinalizer;
            demand(JS_NewClass(rt, nonceClass, &nonceDef) == 0);
            JSValue global = JS_GetGlobalObject(ctx);
            put(ctx, global, "__dmashHost", JS_NewCFunction(ctx, host, "__dmashHost", 1));
            JS_FreeValue(ctx, global);
            if (!worker) {
                const auto file = QDir(profile).filePath("node.sqlite");
                relations = std::make_unique<RelationshipSqlStore>(file);
                inbox = std::make_unique<InboxSqlStore>(file);
            }
            load("@platform");
            if (worker)
                load(target);
            else {
                for (const auto& name : coreModules())
                    load(name);
                load("@nacl-native");
                load("@jobs");
                load("@entry");
            }
        } catch (...) {
            shutdown();
            throw;
        }
    }
    ~Engine() { shutdown(); }
    static QStringList coreModules() {
        return {"vendor/nacl-fast.min.js",   "vendor/blake3.min.js",      "secure_session.js",
                "node_identity.js",          "node_relationships_v4.js",  "node_admission_v4.js",
                "node_registration_v4.js",   "resource_pow.js",           "node_socket_v4.js",
                "node_channel_v4.js",        "probe_primitives_v4.js",    "route_discovery_v4.js",
                "recipient_payload_v4.js",   "node_routing_v4.js",        "node_inbox_v4.js",
                "node_local_delivery_v4.js", "node_local_ownership_v4.js"};
    }
    void check() { demand(!closed && QThread::currentThread() == thread() && !cancel->load()); }
    void load(const QString& name) {
        check();
        demand(coreModules().contains(name) || name == "@platform" ||
               (!worker && (name == "@entry" || name == "@jobs" || name == "@nacl-native")));
        if (loaded.contains(name))
            return;
        const auto path = name == "@platform" ? ":/dmash/native/platform.js"
                          : name == "@entry"  ? ":/dmash/native/runtime_entry.js"
                          : name == "@nacl-native" ? ":/dmash/native/nacl_native.js"
                          : name == "@jobs"   ? ":/dmash/native/job_runtime.js"
                                              : ":/dmash/js/" + name;
        QFile f(path);
        demand(f.open(QIODevice::ReadOnly) && f.size() <= 2 * 1024 * 1024);
        const auto source = f.readAll();
        sourceHashes.insert(name,QString::fromLatin1(CryptoPort::sha256(source).toHex()));
        JSValue value = JS_Eval(ctx, source.constData(), size_t(source.size()),
                                name.toUtf8().constData(), JS_EVAL_TYPE_GLOBAL);
        if (JS_IsException(value)) {
            exception();
            JS_FreeValue(ctx, value);
            throw std::runtime_error("Compiled native module failed");
        }
        JS_FreeValue(ctx, value);
        loaded.insert(name);
    }
    void exception() {
        JSValue error = JS_GetException(ctx);
        JSValue stack = JS_GetPropertyStr(ctx, error, "stack");
        QString frames;
        if (JS_IsString(stack)) {
            size_t length = 0;
            const char* text = JS_ToCStringLen(ctx, &length, stack);
            if (text) {
                frames = QString::fromUtf8(text, qsizetype(qMin(length, size_t(4096))));
                JS_FreeCString(ctx, text);
            }
        }
        JS_FreeValue(ctx, stack);
        JS_FreeValue(ctx, error);
        if (report)
            report({{"event", "error"}, {"code", "JS_EXCEPTION"}, {"stack", frames}});
    }
    void drain() {
        if (closed)
            return;
        for (int i = 0; i < 256; i++) {
            JSContext* job = nullptr;
            const int n = JS_ExecutePendingJob(rt, &job);
            if (n < 0) {
                exception();
                return;
            }
            if (n == 0)
                return;
        }
        if (!drainQueued) {
            drainQueued = true;
            QTimer::singleShot(0, this, [this] {
                drainQueued = false;
                drain();
            });
        }
    }
    void event(const QString& type, int id, const QString& data = {}) {
        if (closed || cancel->load())
            return;
        if(worker && type=="workerInput" && qEnvironmentVariableIsSet("DMASH_NATIVE_BENCH") && report)report({{"event","benchmark-worker-source"},{"sha256",sourceHashes}});
        JSValue global = JS_GetGlobalObject(ctx),
                fn = JS_GetPropertyStr(ctx, global, "__nativeEvent");
        const auto encoded = data.toUtf8();
        JSValue args[] = {JS_NewString(ctx, type.toUtf8().constData()), JS_NewInt32(ctx, id),
                          JS_NewStringLen(ctx, encoded.constData(), size_t(encoded.size()))};
        JSValue result = JS_Call(ctx, fn, global, 3, args);
        for (auto value : args)
            JS_FreeValue(ctx, value);
        JS_FreeValue(ctx, fn);
        JS_FreeValue(ctx, global);
        if (JS_IsException(result))
            exception();
        JS_FreeValue(ctx, result);
        drain();
    }
    void entry(const char* method, JSValue argument = JS_UNDEFINED) {
        check();
        JSValue global = JS_GetGlobalObject(ctx),
                object = JS_GetPropertyStr(ctx, global, "NativeNode"),
                fn = JS_GetPropertyStr(ctx, object, method);
        JSValue result = JS_Call(ctx, fn, object, JS_IsUndefined(argument) ? 0 : 1, &argument);
        JS_FreeValue(ctx, fn);
        JS_FreeValue(ctx, object);
        JS_FreeValue(ctx, global);
        JS_FreeValue(ctx, argument);
        if (JS_IsException(result))
            exception();
        JS_FreeValue(ctx, result);
        drain();
    }
    JSValue json(const QJsonValue& value) {
        QByteArray data;
        if (value.isObject())
            data = QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact);
        else if (value.isArray())
            data = QJsonDocument(value.toArray()).toJson(QJsonDocument::Compact);
        else if (value.isNull())
            return JS_NULL;
        else
            throw std::runtime_error("Native JSON value rejected");
        demand(data.size() <= 524288);
        auto parsed = JS_ParseJSON(ctx, data.constData(), size_t(data.size()), "native-port");
        if (JS_IsException(parsed)) {
            exception();
            throw std::runtime_error("Native JSON allocation failed");
        }
        return parsed;
    }
    bool mayWrite() { return jobs && jobs->current() && jobs->policy().value("enabled").toBool(); }
    JSValue row(const std::optional<EncryptedRow>& value) {
        if (!value)
            return JS_NULL;
        JSValue out = JS_NewObject(ctx);
        put(ctx, out, "key", JS_NewString(ctx, value->key.toUtf8().constData()));
        put(ctx, out, "revision", JS_NewInt64(ctx, value->revision));
        put(ctx, out, "iv", uint8(ctx, value->iv));
        put(ctx, out, "ciphertext", arrayBuffer(ctx, value->ciphertext));
        return out;
    }
    void stopWorker(int id) {
        const auto state = computes.take(id);
        if (!state || state->closed)
            return;
        state->closed = true;
        state->cancel->store(true);
        if (state->engine)
            QMetaObject::invokeMethod(
                state->engine, [engine = state->engine] { engine->shutdown(); },
                Qt::QueuedConnection);
        state->thread->quit();
        if (!state->thread->wait(5000)) {
            // Cancellation is already visible to the VM interrupt handler. Keep
            // the context on its own thread until it exits; never free live JS.
            QObject::connect(state->thread, &QThread::finished, state->thread,
                             &QObject::deleteLater);
            if (report)
                report({{"event", "error"}, {"code", "COMPUTE_STOP_TIMEOUT"}});
            return;
        }
        delete state->thread;
    }
    void shutdown() {
        if (closed)
            return;
        closed = true;
        for (auto timer : timers) {
            timer->stop();
            delete timer;
        }
        timers.clear();
        for (auto socket : sockets) {
            socket->disconnect(this);
            socket->abort();
            delete socket;
        }
        sockets.clear();
        for (int id : computes.keys())
            stopWorker(id);
        batchGuards.clear();
        jobs.reset();
        inbox.reset();
        relations.reset();
        if (ctx) {
            JS_FreeContext(ctx);
            ctx = nullptr;
        }
        if (rt) {
            JS_FreeRuntime(rt);
            rt = nullptr;
        }
    }
    static JSValue host(JSContext* c, JSValueConst, int argc, JSValueConst* argv) {
        auto* self = static_cast<Engine*>(JS_GetContextOpaque(c));
        QString operation;
        try {
            self->check();
            demand(argc >= 1);
            const auto op = string(c, argv[0], 64);
            operation=op;
            auto arg = [&](int index) -> JSValueConst {
                demand(index < argc);
                return argv[index];
            };
            if (op == "benchmarkEnabled")
                return JS_NewBool(c, qEnvironmentVariableIsSet("DMASH_NATIVE_BENCH"));
            if (op == "isWorker")
                return JS_NewBool(c, self->worker);
            if (op == "utf8Encode")
                return arrayBuffer(c, string(c, arg(1)).toUtf8());
            if (op == "utf8Decode") {
                const auto input = bytes(c, arg(1));
                const bool fatal = JS_ToBool(c, arg(2)) == 1, ignoreBOM = JS_ToBool(c, arg(3)) == 1;
                QStringDecoder decoder(QStringDecoder::Utf8,
                                       QStringConverter::Flag::Stateless |
                                           (ignoreBOM ? QStringConverter::Flag::ConvertInitialBom
                                                      : QStringConverter::Flag::Default));
                const QString text = decoder(input);
                demand(!fatal || !decoder.hasError());
                const auto utf8 = text.toUtf8();
                return JS_NewStringLen(c, utf8.constData(), size_t(utf8.size()));
            }
            if (op == "base64Encode") {
                const auto value = bytes(c, arg(1));
                return JS_NewString(c, value.toBase64().constData());
            }
            if (op == "base64Decode") {
                auto value = string(c, arg(1)).toLatin1();
                value.replace(" ", "");
                value.replace("\t", "");
                value.replace("\r", "");
                value.replace("\n", "");
                const auto result =
                    QByteArray::fromBase64Encoding(value, QByteArray::AbortOnBase64DecodingErrors);
                demand(bool(result));
                const auto text = QString::fromLatin1(result.decoded).toUtf8();
                return JS_NewStringLen(c, text.constData(), size_t(text.size()));
            }
            if (op == "url") {
                const auto value = string(c, arg(1), 2048), base = string(c, arg(2), 2048);
                QUrl url(value, QUrl::StrictMode);
                if (!base.isEmpty())
                    url = QUrl(base, QUrl::StrictMode).resolved(url);
                demand(url.isValid() && !url.isRelative());
                JSValue out = JS_NewObject(c);
                const QMap<QByteArray, QString> properties = {
                    {"href", url.toString(QUrl::FullyEncoded)},
                    {"protocol", url.scheme() + ":"},
                    {"hostname", url.host().contains(':') ? "[" + url.host() + "]" : url.host()},
                    {"username", url.userName()},
                    {"password", url.password()},
                    {"hash", url.hasFragment() ? "#" + url.fragment() : QString()}};
                for (auto i = properties.begin(); i != properties.end(); ++i)
                    put(c, out, i.key().constData(),
                        JS_NewString(c, i.value().toUtf8().constData()));
                return out;
            }
            if (op == "nonceCreate") {
                demand(self->worker && self->keyBudget->count < 1024);
                const auto prefix = bytes(c, arg(1), 65536);
                auto value = JS_NewObjectClass(c, nonceClass);
                demand(!JS_IsException(value));
                try {
                    JS_SetOpaque(value, new NativeNonce(prefix, self->keyBudget));
                } catch (...) {
                    JS_FreeValue(c, value);
                    throw;
                }
                return value;
            }
            if (op == "nonceSearch") {
                demand(self->worker);
                auto* hasher = static_cast<NativeNonce*>(JS_GetOpaque2(c, arg(1), nonceClass));demand(hasher);
                double startValue=0;
                demand(JS_IsNumber(arg(2)) && JS_ToFloat64(c,&startValue,arg(2))==0 && startValue>=0 && startValue<=9007199254740991.0 && startValue==qint64(startValue));
                const auto start=qint64(startValue);
                const int count = integer(c,arg(3),1,4096), difficulty = integer(c,arg(4),0,256);
                demand(start <= 9007199254740991LL-count+1);
                const auto found=hasher->hash.search(quint64(start),count,difficulty,self->cancel.get());
                if(!found)return JS_NULL;
                auto out=JS_NewObject(c);put(c,out,"nonce",JS_NewInt64(c,qint64(found->nonce)));put(c,out,"digest",uint8(c,found->digest));return out;
            }
            if (op == "nonceHash") {
                auto* hasher = static_cast<NativeNonce*>(JS_GetOpaque2(c, arg(1), nonceClass));
                demand(hasher);
                double high = 0, low = 0;
                demand(JS_IsNumber(arg(2)) && JS_IsNumber(arg(3)) &&
                       JS_ToFloat64(c, &high, arg(2)) == 0 && JS_ToFloat64(c, &low, arg(3)) == 0);
                demand(high >= 0 && high <= 4294967295.0 && low >= 0 && low <= 4294967295.0 &&
                       high == quint64(high) && low == quint64(low));
                return uint8(c, hasher->hash.digest((quint64(high) << 32) | quint64(low)));
            }
            if (op == "monotonic") {
                const double now = double(self->clock.nsecsElapsed()) / 1000000.0;
                if (self->worker && qEnvironmentVariableIsSet("DMASH_NATIVE_BENCH")) {
                    ++self->clockCalls;
                    if (self->clockCalls == 1)
                        self->firstClock = now;
                    if (self->clockCalls == 2 && self->report)
                        self->report({{"event", "worker-clock-sample"},
                                      {"clockCalls", 2},
                                      {"elapsedMs", now - self->firstClock}});
                }
                return JS_NewFloat64(c, now);
            }
            if (op == "randomFill") {
                size_t offset = 0, n = 0, bpe = 0, total = 0;
                JSValue buffer = JS_GetTypedArrayBuffer(c, arg(1), &offset, &n, &bpe);
                demand(!JS_IsException(buffer));
                auto* p = JS_GetArrayBuffer(c, &total, buffer);
                if (n > 65536 || offset > total || n > total - offset || (!p && n)) {
                    JS_FreeValue(c, buffer);
                    throw std::runtime_error("Random buffer rejected");
                }
                auto random = CryptoPort::random(int(n));
                if (n) {
                    memcpy(p + offset, random.constData(), n);
                    OPENSSL_cleanse(random.data(), n);
                }
                JS_FreeValue(c, buffer);
                return JS_UNDEFINED;
            }
            if (op == "keyImport") {
                auto value = bytes(c, arg(1));
                WipeBytes wipe{value};
                const auto algorithm = string(c, arg(2), 16), usages = string(c, arg(3), 64);
                demand(algorithm == "HMAC" || algorithm == "HKDF" || algorithm == "AES-GCM");
                if (algorithm == "AES-GCM")
                    demand(value.size() == 16 || value.size() == 24 || value.size() == 32);
                demand(self->keyBudget->count < 1024 &&
                       self->keyBudget->bytes + value.size() <= 16 * 1024 * 1024);
                auto* k = new NativeKey{std::move(value), algorithm, usages, self->keyBudget};
                ++self->keyBudget->count;
                self->keyBudget->bytes += k->bytes.size();
                JSValue object = JS_NewObjectClass(c, keyClass);
                if (JS_IsException(object)) {
                    delete k;
                    return object;
                }
                JS_SetOpaque(object, k);
                return object;
            }
            if (op == "ed25519Verify")
                return JS_NewBool(c, CryptoPort::ed25519Verify(bytes(c,arg(1)),bytes(c,arg(2)),bytes(c,arg(3))));
            if (op == "x25519")
                return uint8(c, CryptoPort::x25519(bytes(c,arg(1)),bytes(c,arg(2))));
            if (op == "sha256")
                return arrayBuffer(c, CryptoPort::sha256(bytes(c, arg(1))));
            if (op == "hmac")
                return arrayBuffer(c, CryptoPort::hmacSha256(key(c, arg(1), "HMAC", "sign")->bytes,
                                                             bytes(c, arg(2))));
            if (op == "hmacVerify") {
                const auto signature = bytes(c, arg(2)),
                           expected = CryptoPort::hmacSha256(
                               key(c, arg(1), "HMAC", "verify")->bytes, bytes(c, arg(3)));
                return JS_NewBool(c, signature.size() == expected.size() &&
                                         CRYPTO_memcmp(signature.constData(), expected.constData(),
                                                       size_t(expected.size())) == 0);
            }
            if (op == "hkdf" || op == "hkdfKey")
                return arrayBuffer(
                    c, CryptoPort::hkdfSha256(key(c, arg(1), "HKDF", op == "hkdfKey" ? "deriveKey" : "deriveBits")->bytes,
                                              bytes(c, arg(2)), bytes(c, arg(3)),
                                              integer(c, arg(4), 1, 8160)));
            if (op == "encrypt" || op == "decrypt")
                return arrayBuffer(
                    c,
                    CryptoPort::aesGcm(
                        op == "encrypt",
                        key(c, arg(1), "AES-GCM", op == "encrypt" ? "encrypt" : "decrypt")->bytes,
                        bytes(c, arg(2)), bytes(c, arg(3)), bytes(c, arg(4)),
                        integer(c, arg(5), 32, 128)));
            if (op == "timerStart") {
                const int id = integer(c, arg(1), 1), delay = integer(c, arg(2));
                demand(self->timers.size() < 1024 && !self->timers.contains(id));
                auto* timer = new QTimer(self);
                timer->setSingleShot(true);
                self->timers.insert(id, timer);
                QObject::connect(timer, &QTimer::timeout, self, [self, id, timer] {
                    self->timers.remove(id);
                    timer->deleteLater();
                    self->event("timer", id);
                });
                timer->start(delay);
                return JS_UNDEFINED;
            }
            if (op == "timerStop") {
                const int id = integer(c, arg(1));
                if (auto* timer = self->timers.take(id)) {
                    timer->stop();
                    delete timer;
                }
                return JS_UNDEFINED;
            }
            if (op == "importScript") {
                demand(self->worker);
                self->load(string(c, arg(1), 128));
                return JS_UNDEFINED;
            }
            if (op == "workerReply") {
                demand(self->worker && bool(self->reply));
                const auto data = string(c, arg(1), MaxClone);
                if (qEnvironmentVariableIsSet("DMASH_NATIVE_BENCH") && self->report) {
                    const auto proof =
                        QJsonDocument::fromJson(data.toUtf8()).object().value("proof").toObject();
                    if (proof.contains("nonce"))
                        self->report({{"event", "worker-proof"},
                                      {"nonce", proof.value("nonce")},
                                      {"difficulty", proof.value("difficulty")},
                                      {"elapsedMs", proof.value("elapsed_ms")}});
                }
                self->reply(data);
                return JS_UNDEFINED;
            }
            if(op=="workerBenchmark" || op=="workerBenchmarkError"){
                demand(self->worker && qEnvironmentVariableIsSet("DMASH_NATIVE_BENCH"));
                QJsonObject event;
                if(op=="workerBenchmark"){
                    double crossing=0,batch=0;demand(JS_IsNumber(arg(1)) && JS_IsNumber(arg(2)) && JS_ToFloat64(c,&crossing,arg(1))==0 && JS_ToFloat64(c,&batch,arg(2))==0 && crossing>=0 && crossing<=1000000 && batch>=0 && batch<=1000000);
                    event={{"event","benchmark-nonce-batch"},{"attempts",4096},{"crossingMs",crossing},{"batchMs",batch}};
                }else{
                    const auto phase=string(c,arg(1),16);demand(phase=="search" || phase=="factory");
                    event={{"event","benchmark-nonce-"+phase+"-error"},{"name",string(c,arg(2),64)},{"code",string(c,arg(3),160)}};
                }
                if(self->report)
                    self->report(event);
                return JS_UNDEFINED;
            }
            if (op == "workerNew") {
                demand(!self->worker && self->computes.size() < 2);
                const auto target = string(c, arg(1), 128);
                demand(target == "node_channel_v4.js" || target == "node_identity.js");
                if (activeComputes.fetch_add(1) >= 2) {
                    activeComputes.fetch_sub(1);
                    throw std::runtime_error("Compute quota");
                }
                const int id = ++self->nextWorker;
                auto state = std::make_shared<Compute>();
                state->thread = new QThread();
                QObject::connect(state->thread, &QThread::finished,
                                 [] { activeComputes.fetch_sub(1); });
                state->context = new QObject();
                state->context->moveToThread(state->thread);
                self->computes.insert(id, state);
                QPointer<Engine> owner(self);
                QObject::connect(state->thread, &QThread::finished, state->context,
                                 &QObject::deleteLater);
                QObject::connect(
                    state->thread, &QThread::started, state->context, [state, owner, id, target] {
                        try {
                            auto* engine = new Engine({}, target, state->cancel, state->context);
                            engine->report = [owner, id](QJsonObject event) {
                                event.insert("worker", id);
                                if (owner)
                                    QMetaObject::invokeMethod(
                                        owner,
                                        [owner, event] {
                                            if (owner && owner->report)
                                                owner->report(event);
                                        },
                                        Qt::QueuedConnection);
                            };
                            engine->reply = [owner, id](const QString& data) {
                                if (owner)
                                    QMetaObject::invokeMethod(
                                        owner,
                                        [owner, id, data] {
                                            if (owner)
                                                owner->event("workerMessage", id, data);
                                        },
                                        Qt::QueuedConnection);
                            };
                            QMetaObject::invokeMethod(
                                owner,
                                [state, owner, engine, id] {
                                    if (!owner || state->closed)
                                        return;
                                    state->engine = engine;
                                    for (const auto& data : state->pending)
                                        QMetaObject::invokeMethod(
                                            engine,
                                            [engine, data] {
                                                engine->event("workerInput", 0, data);
                                            },
                                            Qt::QueuedConnection);
                                    state->pending.clear();
                                },
                                Qt::QueuedConnection);
                        } catch (...) {
                            if (owner)
                                QMetaObject::invokeMethod(
                                    owner,
                                    [owner, id] {
                                        if (owner)
                                            owner->event("workerError", id);
                                    },
                                    Qt::QueuedConnection);
                        }
                    });
                state->thread->start();
                return JS_NewInt32(c, id);
            }
            if (op == "workerPost") {
                demand(!self->worker);
                const int id = integer(c, arg(1), 1);
                const auto data = string(c, arg(2), MaxClone);
                const auto state = self->computes.value(id);
                demand(state && !state->closed);
                if (state->engine)
                    QMetaObject::invokeMethod(
                        state->engine,
                        [engine = state->engine, data] { engine->event("workerInput", 0, data); },
                        Qt::QueuedConnection);
                else {
                    demand(state->pending.size() < 2);
                    state->pending.append(data);
                }
                return JS_UNDEFINED;
            }
            if (op == "workerStop") {
                demand(!self->worker);
                self->stopWorker(integer(c, arg(1), 1));
                return JS_UNDEFINED;
            }
            demand(!self->worker);
            if (op == "relRead")
                return self->row(self->relations->read(string(c, arg(1), 64)));
            if (op == "relCas") {
                const auto name = string(c, arg(1), 64);
                std::optional<qint64> revision;
                if (!JS_IsNull(arg(2))) {
                    int64_t rev = 0;
                    demand(JS_ToInt64(c, &rev, arg(2)) == 0);
                    revision = rev;
                }
                return JS_NewBool(c, self->relations->cas(name, revision, bytes(c, arg(3), 12),
                                                          bytes(c, arg(4), 1024 * 1024),
                                                          JS_ToBool(c, arg(5)) == 1,
                                                          integer(c, arg(6), 1, 65536)));
            }
            if (op == "inboxReconcile") {
                self->inbox->reconcile();
                return JS_UNDEFINED;
            }
            if (op == "inboxRead")
                return self->row(self->inbox->read(string(c, arg(1), 520)));
            if (op == "inboxAll" || op == "inboxBindings") {
                const auto rows =
                    op == "inboxAll" ? self->inbox->all() : self->inbox->allBindings();
                auto array = JS_NewArray(c);
                demand(!JS_IsException(array));
                for (qsizetype i = 0; i < rows.size(); ++i) {
                    if (JS_SetPropertyUint32(c, array, uint32_t(i), self->row(rows[i])) < 0) {
                        JS_FreeValue(c, array);
                        return JS_EXCEPTION;
                    }
                }
                return array;
            }
            if (op == "inboxCas" || op == "inboxPromote") {
                auto revision = [&](int index) -> std::optional<qint64> {
                    if (JS_IsNull(arg(index)))
                        return std::nullopt;
                    double n = 0;
                    demand(JS_IsNumber(arg(index)) && JS_ToFloat64(c, &n, arg(index)) == 0 &&
                           n >= 1 && n <= 9007199254740991.0 && n == qint64(n));
                    return qint64(n);
                };
                const int at = op == "inboxCas" ? 3 : 5;
                std::optional<EncryptedRow> row;
                if (!JS_IsNull(arg(at)))
                    row = EncryptedRow{QString(), 0, bytes(c, arg(at), 12),
                                       bytes(c, arg(at + 1), 65536)};
                else
                    demand(JS_IsNull(arg(at + 1)));
                bool changed = false;
                if (op == "inboxCas")
                    changed = self->inbox->cas(string(c, arg(1), 520), revision(2), row);
                else {
                    const auto source = revision(2);
                    demand(source.has_value());
                    changed = self->inbox->promote(string(c, arg(1), 64), *source,
                                                   string(c, arg(3), 64), revision(4), row);
                }
                return JS_NewBool(c, changed);
            }
            auto safe = [&](int index, qint64 minimum = 0) -> qint64 {
                double n = 0;
                demand(JS_IsNumber(arg(index)) && JS_ToFloat64(c, &n, arg(index)) == 0 &&
                       n >= minimum && n <= 9007199254740991.0 && n == qint64(n));
                return qint64(n);
            };
            const auto now = []() { return QDateTime::currentMSecsSinceEpoch(); };
            if (op == "jobsOpen") {
                demand(!self->jobs);
                auto storage = bytes(c, arg(2), 32);
                WipeBytes wipe{storage};
                self->jobs =
                    std::make_unique<JobLedger>(QDir(self->profilePath).filePath("node.sqlite"),
                                                string(c, arg(1), 64), storage);
                try {
                    self->jobs->acquire(safe(3, 1), safe(4, 1), true, JS_ToBool(c, arg(5)) == 1);
                } catch (...) {
                    if (self->bootstrapFloors)
                        self->bootstrapFloors(self->jobs->bootstrapState());
                    throw;
                }
                return self->json(self->jobs->policy());
            }
            if (op == "jobsInstall")
                return JS_NewString(c, self->jobs
                                           ->installDestination(string(c, arg(1), 64),
                                                                bytes(c, arg(2), 32768), safe(3, 1),
                                                                safe(4, 1), now())
                                           .toLatin1()
                                           .constData());
            if (op == "jobsDestination") {
                const auto value =
                    self->jobs->destination(string(c, arg(1), 64), string(c, arg(2), 64));
                return value ? self->json(*value) : JS_NULL;
            }
            if (op == "jobsAccept" || op == "jobsExisting") {
                const auto scope = string(c, arg(1), 64), destination = string(c, arg(2), 64),
                           operation = string(c, arg(3), 128);
                const auto body = bytes(c, arg(4), 65536);
                const auto expires = safe(5, 1);
                if (op == "jobsExisting") {
                    const auto value =
                        self->jobs->existing(scope, destination, operation, body, expires);
                    return value ? self->json(*value) : JS_NULL;
                }
                return self->json(
                    self->jobs->accept(scope, destination, operation, body, expires, now()));
            }
            if (op == "jobsRead") {
                const auto value = self->jobs->job(string(c, arg(1), 64), string(c, arg(2), 64));
                return value ? self->json(*value) : JS_NULL;
            }
            if (op == "jobsDue") {
                QJsonArray out;
                for (const auto& value : self->jobs->due(now(), integer(c, arg(1), 1, 4),
                                                         argc > 2 && JS_ToBool(c, arg(2)) == 1))
                    out.append(value);
                return self->json(out);
            }
            if (op == "jobsClaim") {
                const auto value = self->jobs->claim(string(c, arg(1), 64), safe(2, 1), now(),
                                                     argc > 3 && JS_ToBool(c, arg(3)) == 1);
                return value ? self->json(*value) : JS_NULL;
            }
            if (op == "jobsDefer")
                return JS_NewBool(c, self->jobs->defer(string(c, arg(1), 64), safe(2, 1),
                                                       string(c, arg(3), 32), safe(4), now()));
            if (op == "jobsFinish")
                return JS_NewBool(c,
                                  self->jobs->finish(string(c, arg(1), 64), string(c, arg(2), 64),
                                                     string(c, arg(3), 32), safe(4), now()));
            if (op == "jobsCancel")
                return JS_NewBool(
                    c, self->jobs->cancel(string(c, arg(1), 64), string(c, arg(2), 64), now()));
            if (op == "jobsMaySend")
                return JS_NewBool(
                    c, self->jobs->maySend(string(c, arg(1), 64), string(c, arg(2), 64), now()));
            if (op == "jobsPrune")
                return JS_NewInt32(c, self->jobs->prune(now()));
            if (op == "jobsNext") {
                const auto value = self->jobs->nextDeadline();
                return value ? JS_NewInt64(c, *value) : JS_NULL;
            }
            if (op == "jobsPolicy")
                return self->json(self->jobs->policy());
            if (op == "jobsSetPolicy") {
                self->jobs->setPolicy(safe(1, 1), JS_ToBool(c, arg(2)) == 1,
                                      JS_ToBool(c, arg(3)) == 1);
                return self->json(self->jobs->policy());
            }
            if (op == "jobsRevoke")
                return self->json(self->jobs->revoke(safe(1, 1), safe(2, 1)));
            if (op == "batchGuardBegin") {
                const int socket = integer(c, arg(1), 1);
                demand(self->sockets.contains(socket) && !self->batchGuards.contains(socket) &&
                       self->mayWrite());
                const auto raw = string(c, arg(2), 8192).toUtf8();
                const auto doc = QJsonDocument::fromJson(raw);
                demand(doc.isArray() && doc.array().size() <= 32);
                BatchGuard guard;
                guard.id = QString::fromLatin1(CryptoPort::random(16).toHex());
                for (const auto& value : doc.array()) {
                    demand(value.isObject());
                    const auto object = value.toObject();
                    demand(object.size() == 2 && object.value("id").isString() &&
                           object.value("attemptToken").isString());
                    const auto id = object.value("id").toString(),
                               token = object.value("attemptToken").toString();
                    demand(self->jobs->maySend(id, token, now()));
                    guard.jobs.append({id, token});
                }
                self->batchGuards.insert(socket, guard);
                return JS_NewString(c, guard.id.toLatin1().constData());
            }
            if (op == "batchGuardEnd") {
                const int socket = integer(c, arg(1), 1);
                if (self->batchGuards.value(socket).id == string(c, arg(2), 32))
                    self->batchGuards.remove(socket);
                return JS_UNDEFINED;
            }
            if (op == "localReply") {
                const auto id = string(c, arg(1), 64);
                const auto data = string(c, arg(2), 524288).toUtf8();
                QJsonParseError error;
                const auto doc = QJsonDocument::fromJson(data, &error);
                demand(error.error == QJsonParseError::NoError && doc.isObject());
                if (self->localReply)
                    self->localReply(id, doc.object());
                return JS_UNDEFINED;
            }
            if (op == "socketNew") {
                demand(self->sockets.size() < 8 && self->mayWrite());
                const auto text = string(c, arg(1), 2048);
                const QUrl url(text, QUrl::StrictMode);
                demand(
                    url.isValid() && !url.isRelative() && url.userInfo().isEmpty() &&
                    !url.hasFragment() &&
                    (url.scheme() == "wss" ||
                     (url.scheme() == "ws" && (url.host() == "127.0.0.1" ||
                                               url.host() == "localhost" || url.host() == "::1"))));
                const int id = ++self->nextSocket;
                auto* socket = new QWebSocket(QString(), QWebSocketProtocol::VersionLatest, self);
                socket->setMaxAllowedIncomingFrameSize(MaxFrame);
                socket->setMaxAllowedIncomingMessageSize(MaxFrame);
                self->sockets.insert(id, socket);
                QObject::connect(socket, &QWebSocket::connected, self,
                                 [self, id] { self->event("open", id); });
                QObject::connect(socket, &QWebSocket::textMessageReceived, self,
                                 [self, id](const QString& data) {
                                     if (data.size() > MaxFrame) {
                                         if (auto* s = self->sockets.value(id))
                                             s->abort();
                                         return;
                                     }
                                     self->event("message", id, data);
                                 });
                QObject::connect(socket, &QWebSocket::binaryMessageReceived, self,
                                 [socket](const QByteArray&) { socket->abort(); });
                QObject::connect(socket, &QWebSocket::disconnected, self, [self, id, socket] {
                    self->sockets.remove(id);
                    self->event("close", id);
                    socket->deleteLater();
                });
                QObject::connect(
                    socket, &QWebSocket::errorOccurred, self,
                    [self, id](QAbstractSocket::SocketError) { self->event("error", id); });
                socket->open(url);
                return JS_NewInt32(c, id);
            }
            if (op == "socketBuffered") {
                const auto* s = self->sockets.value(integer(c, arg(1), 1));
                return JS_NewFloat64(c, s ? double(s->bytesToWrite()) : 0);
            }
            if (op == "socketSend") {
                auto* s = self->sockets.value(integer(c, arg(1), 1));
                const auto text = string(c, arg(2));
                demand(self->mayWrite());
                const int socket = integer(c, arg(1), 1);
                if (self->batchGuards.contains(socket))
                    for (const auto& guard : self->batchGuards.value(socket).jobs)
                        demand(self->jobs->maySend(guard.first, guard.second,
                                                   QDateTime::currentMSecsSinceEpoch()));
                demand(s && s->state() == QAbstractSocket::ConnectedState &&
                       s->bytesToWrite() + text.toUtf8().size() <= 4 * 1024 * 1024);
                demand(s->sendTextMessage(text) >= 0);
                return JS_UNDEFINED;
            }
            if (op == "socketClose") {
                auto* s = self->sockets.value(integer(c, arg(1), 1));
                if (s)
                    s->close(QWebSocketProtocol::CloseCode(integer(c, arg(2), 1000, 4999)),
                             string(c, arg(3), 123));
                return JS_UNDEFINED;
            }
            if (op == "report") {
                const auto raw = string(c, arg(1), 65536).toUtf8();
                QJsonParseError error;
                const auto doc = QJsonDocument::fromJson(raw, &error);
                demand(error.error == QJsonParseError::NoError && doc.isObject());
                if (self->report)
                    self->report(doc.object());
                return JS_UNDEFINED;
            }
            throw std::runtime_error("Native operation unavailable");
        } catch (const std::exception& failure) {
            if(qEnvironmentVariableIsSet("DMASH_NATIVE_BENCH") && self->report)self->report({{"event","benchmark-port-error"},{"operation",operation},{"code",QString::fromUtf8(failure.what()).left(160)}});
            return JS_ThrowTypeError(c, "Native port rejected operation");
        }
    }
};
} // namespace
static void privateProfile(const QString& profile) {
#ifdef Q_OS_UNIX
    const auto broad = QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup |
                       QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther;
    QFileInfo info(profile);
    if (!info.exists()) {
        const QFileInfo parent(info.absolutePath());
        demand(parent.isDir() && !parent.isSymLink() && parent.ownerId() == geteuid() &&
               !(parent.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)));
        demand(QDir(parent.absoluteFilePath()).mkdir(info.fileName()));
        demand(QFile::setPermissions(info.absoluteFilePath(), QFileDevice::ReadOwner |
                                                                  QFileDevice::WriteOwner |
                                                                  QFileDevice::ExeOwner));
        info.refresh();
    }
    demand(info.isDir() && !info.isSymLink() && info.ownerId() == geteuid() &&
           !(info.permissions() & broad));
    for (const auto& name : {"node.sqlite", "node.sqlite-wal", "node.sqlite-shm", "owner.lock"}) {
        const QFileInfo file(QDir(profile).filePath(name));
        if (file.exists() || file.isSymLink())
            demand(file.isFile() && !file.isSymLink() && file.ownerId() == geteuid() &&
                   !(file.permissions() & broad));
    }
#elif defined(Q_OS_WIN)
    windowsLocal::ensurePrivateProfile(profile.toStdWString());
#else
    Q_UNUSED(profile);
    throw std::runtime_error("Native protected-storage ACL not implemented on this platform");
#endif
}
class JsActor::Impl {
  public:
    JsActor* owner;
    quint64 generation = 1;
    bool closed = false, initializationStarted = false;
    quint64 transportGeneration = 0;
    QLockFile lock;
    TransportBundle bundle;
    QVector<EndpointGrant> endpoints;
    std::unique_ptr<Engine> engine;
    Impl(JsActor* outer, const QString& profile)
        : owner(outer), lock(QDir(profile).filePath("owner.lock")) {
        privateProfile(profile);
        lock.setStaleLockTime(0);
        demand(lock.tryLock(0));
        engine =
            std::make_unique<Engine>(profile, QString(), std::make_shared<std::atomic_bool>(false));
        for (const auto& name :
             {"node.sqlite", "node.sqlite-wal", "node.sqlite-shm", "owner.lock"}) {
            const auto path = QDir(profile).filePath(name);
            if (QFile::exists(path))
#ifdef Q_OS_WIN
                windowsLocal::requirePrivateFile(path.toStdWString());
#else
                demand(
                    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner));
#endif
        }
        QPointer<JsActor> receiver(outer);
        const auto generation = this->generation;
        engine->bootstrapFloors = [receiver, generation](const QJsonObject& floors) {
            QMetaObject::invokeMethod(
                receiver,
                [receiver, generation, floors] {
                    if (receiver && receiver->impl_ && !receiver->impl_->closed &&
                        receiver->impl_->generation == generation && receiver->onBootstrapFloors)
                        receiver->onBootstrapFloors(floors);
                },
                Qt::QueuedConnection);
        };
        engine->localReply = [receiver, generation](const QString& id, const QJsonObject& result) {
            if (receiver)
                QMetaObject::invokeMethod(
                    receiver,
                    [receiver, generation, id, result] {
                        if (receiver && receiver->impl_ && !receiver->impl_->closed &&
                            receiver->impl_->generation == generation && receiver->onLocalReply)
                            receiver->onLocalReply(id, result);
                    },
                    Qt::QueuedConnection);
        };
        engine->report = [receiver, generation](const QJsonObject& event) {
            if (receiver)
                QMetaObject::invokeMethod(
                    receiver,
                    [receiver, event, generation] {
                        if (receiver && receiver->impl_ && !receiver->impl_->closed &&
                            receiver->impl_->generation == generation && receiver->impl_->engine &&
                            receiver->onEvent)
                            receiver->onEvent(event);
                    },
                    Qt::QueuedConnection);
        };
    }
};
JsActor::JsActor(const QString& profile, QObject* parent)
    : QObject(parent), impl_(std::make_unique<Impl>(this, profile)) {}
JsActor::~JsActor() { close(); }
void JsActor::initialize(TransportBundle&& bundle, qint64 policyRevision) {
    demand(QThread::currentThread() == thread() && impl_ && !impl_->closed && impl_->engine);
    demand(!impl_->initializationStarted);
    impl_->initializationStarted = true;
    impl_->transportGeneration = bundle.generation;
    impl_->bundle = std::move(bundle);
    impl_->endpoints = impl_->bundle.endpoints;
    auto* c = impl_->engine->ctx;
    JSValue config = JS_NewObject(c);
    demand(policyRevision >= 1 && policyRevision <= 9007199254740991LL);
    put(c, config, "transportGeneration", JS_NewInt64(c, impl_->bundle.generation));
    put(c, config, "policyRevision", JS_NewInt64(c, policyRevision));
    put(c, config, "directEnabled", JS_NewBool(c, impl_->bundle.directEnabled));
    put(c, config, "seed", uint8(c, impl_->bundle.nodeSeed));
    put(c, config, "storageKey", uint8(c, impl_->bundle.storageKey));
    put(c, config, "baseNcrh", uint8(c, impl_->bundle.baseNcrh));
    impl_->engine->entry("initialize", config);
    impl_->bundle.clear();
}
void JsActor::openLocalSession(const QString& id, bool broker) {
    demand(QThread::currentThread() == thread() && impl_ && !impl_->closed && impl_->engine);
    auto* c = impl_->engine->ctx;
    JSValue value = JS_NewObject(c);
    put(c, value, "connectionId", JS_NewString(c, id.toLatin1().constData()));
    put(c, value, "role", JS_NewString(c, broker ? "broker" : "owner"));
    impl_->engine->entry("openLocal", value);
}
void JsActor::closeLocalSession(const QString& id) {
    if (!impl_ || impl_->closed || !impl_->engine)
        return;
    demand(QThread::currentThread() == thread());
    impl_->engine->entry("closeLocal", JS_NewString(impl_->engine->ctx, id.toLatin1().constData()));
}
void JsActor::dispatchLocal(const QString& connection, const QString& id, const QString& method,
                            const QJsonObject& params) {
    demand(QThread::currentThread() == thread() && impl_ && !impl_->closed && impl_->engine);
    QJsonObject value{
        {"connectionId", connection}, {"id", id}, {"method", method}, {"params", params}};
    impl_->engine->entry("dispatchLocal", impl_->engine->json(value));
}
QJsonObject JsActor::transportPolicy() {
    demand(QThread::currentThread() == thread() && impl_ && !impl_->closed && impl_->engine &&
           impl_->engine->jobs);
    return impl_->engine->jobs->policy();
}
QJsonObject JsActor::revokeTransport() {
    const auto policy = transportPolicy();
    if (policy.value("transportGeneration").toInteger() > qint64(impl_->transportGeneration))
        return policy;
    const auto next = policy.value("policyRevision").toInteger() + 1;
    demand(next <= 9007199254740991LL);
    return impl_->engine->jobs->revoke(policy.value("transportGeneration").toInteger(), next);
}
void JsActor::connectPeer(int index) {
    demand(QThread::currentThread() == thread() && impl_ && !impl_->closed && impl_->engine);
    demand(index >= 0 && index < impl_->endpoints.size());
    auto* c = impl_->engine->ctx;
    const auto& e = impl_->endpoints[index];
    JSValue peer = JS_NewObject(c);
    put(c, peer, "index", JS_NewInt32(c, index));
    put(c, peer, "url", JS_NewString(c, e.url.toString(QUrl::FullyEncoded).toUtf8().constData()));
    put(c, peer, "nodeId", JS_NewString(c, e.nodeId.toLatin1().constData()));
    impl_->engine->entry("connect", peer);
}
void JsActor::queryService(int index) {
    demand(QThread::currentThread() == thread() && impl_ && !impl_->closed && impl_->engine);
    demand(index >= 0 && index < impl_->endpoints.size());
    impl_->engine->entry("query", JS_NewInt32(impl_->engine->ctx, index));
}
void JsActor::snapshot() {
    demand(QThread::currentThread() == thread() && impl_ && !impl_->closed && impl_->engine);
    impl_->engine->entry("snapshot");
}
void JsActor::close() {
    if (!impl_ || !impl_->engine)
        return;
    demand(QThread::currentThread() == thread());
    impl_->closed = true;
    ++impl_->generation;
    impl_->engine->entry("stop");
    impl_->engine.reset();
    impl_->bundle.clear();
    impl_->lock.unlock();
}
} // namespace dmash

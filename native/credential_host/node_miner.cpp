#include "node_miner.h"
#include <QFile>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <quickjs.h>
static void initMinerResource() { Q_INIT_RESOURCE(node_miner); }
namespace dmash::credential {
namespace {
void need(bool b, const char* code) {
    if (!b)
        throw broker::Error(code);
}
struct Js {
    JSRuntime* runtime = JS_NewRuntime();
    JSContext* context = nullptr;
    Js() {
        need(runtime, "NODE_POW_ENGINE_FAILED");
        JS_SetMemoryLimit(runtime, 32 * 1024 * 1024);
        context = JS_NewContext(runtime);
        need(context, "NODE_POW_ENGINE_FAILED");
    }
    ~Js() {
        if (context)
            JS_FreeContext(context);
        if (runtime)
            JS_FreeRuntime(runtime);
    }
    void eval(const QByteArray& source) {
        auto v = JS_Eval(context, source.constData(), size_t(source.size()), "node-pow",
                         JS_EVAL_TYPE_GLOBAL);
        bool ok = !JS_IsException(v);
        JS_FreeValue(context, v);
        need(ok, "NODE_POW_ENGINE_FAILED");
    }
};
} // namespace
QString nodePublicId(const QByteArray& seed) {
    need(seed.size() == 32, "NODE_SEED_INVALID");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr,
                                        reinterpret_cast<const unsigned char*>(seed.constData()),
                                        32),
        EVP_PKEY_free);
    need(bool(key), "NODE_CRYPTO_FAILED");
    QByteArray pub(32, Qt::Uninitialized);
    size_t n = 32;
    need(EVP_PKEY_get_raw_public_key(key.get(), reinterpret_cast<unsigned char*>(pub.data()), &n) ==
                 1 &&
             n == 32,
         "NODE_CRYPTO_FAILED");
    return QString::fromLatin1(pub.toHex());
}
QByteArray verifyOrMineNodeSeed(const QByteArray& existing, broker::RootCodec::Current current) {
    need(current && current(), "CREDENTIAL_CANCELLED");
    initMinerResource();
    Js js;
    QFile script(":/dmash-node-miner/blake3.min.js");
    need(script.open(QIODevice::ReadOnly), "NODE_POW_ENGINE_FAILED");
    js.eval(script.readAll());
    js.eval("function __dmashNodePow(hex){const b=new Uint8Array(64);for(let "
            "i=0;i<64;i++)b[i]=hex.charCodeAt(i);const h=DmashBlake3.blake3(b);return "
            "h[0]===5&&h[1]===32;}");
    auto global = JS_GetGlobalObject(js.context);
    auto fn = JS_GetPropertyStr(js.context, global, "__dmashNodePow");
    JS_FreeValue(js.context, global);
    struct FnGuard {
        JSContext* c;
        JSValue v;
        ~FnGuard() { JS_FreeValue(c, v); }
    } guard{js.context, fn};
    QByteArray seed = existing;
    seed.detach();
    try {
        for (quint64 trial = 0; trial < 4 * 1024 * 1024; ++trial) {
            if ((trial & 63) == 0)
                need(current(), "CREDENTIAL_CANCELLED");
            if (existing.isEmpty()) {
                seed.resize(32);
                need(RAND_bytes(reinterpret_cast<unsigned char*>(seed.data()), 32) == 1,
                     "NODE_CRYPTO_FAILED");
            }
            auto hex = nodePublicId(seed).toLatin1();
            auto arg = JS_NewStringLen(js.context, hex.constData(), size_t(hex.size()));
            auto result = JS_Call(js.context, fn, JS_UNDEFINED, 1, &arg);
            JS_FreeValue(js.context, arg);
            bool exception = JS_IsException(result),
                 valid = !exception && JS_ToBool(js.context, result) == 1;
            JS_FreeValue(js.context, result);
            need(!exception, "NODE_POW_ENGINE_FAILED");
            if (valid) {
                need(current(), "CREDENTIAL_CANCELLED");
                return seed;
            }
            need(existing.isEmpty(), "NODE_IDENTITY_POW_INVALID");
        }
        throw broker::Error("NODE_POW_SEARCH_EXHAUSTED");
    } catch (...) {
        OPENSSL_cleanse(seed.data(), size_t(seed.size()));
        throw;
    }
}
} // namespace dmash::credential

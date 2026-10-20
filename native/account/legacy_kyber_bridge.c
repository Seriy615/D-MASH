#include "vendor/kyber.h"
#include "vendor/wasm2c/wasm-rt-impl.h"
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
struct w2c_a {
    w2c_dmash__legacy__kyber *module;
};
static uint8_t *span(struct w2c_a *imports, u32 offset, u32 length) {
    wasm_rt_memory_t *memory = &imports->module->w2c_c;
    if ((uint64_t)offset + length > memory->size)
        wasm_rt_trap(WASM_RT_TRAP_OOB);
    return memory->data + offset;
}
static u32 read32(struct w2c_a *imports, u32 offset) {
    const uint8_t *p = span(imports, offset, 4);
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
/* Original Emscripten heap growth aborts OOM; never silently change that profile. */
u32 w2c_a_a(struct w2c_a *imports, u32 requested) {
    (void)imports;
    (void)requested;
    wasm_rt_trap(WASM_RT_TRAP_EXHAUSTION);
    return 0;
}
/* The exact artifact has one ASM_CONSTS callback1476 with signature "pi". */
u32 w2c_a_b(struct w2c_a *imports, u32 code, u32 signature, u32 arguments) {
    const uint8_t *sig = span(imports, signature, 3);
    if (code != 1476 || sig[0] != 'p' || sig[1] != 'i' || sig[2] != 0)
        wasm_rt_trap(WASM_RT_TRAP_UNREACHABLE);
    const u32 destination = read32(imports, arguments), length = read32(imports, arguments + 4);
    if (length > 65536 || length > INT_MAX ||
        RAND_bytes(span(imports, destination, length), (int)length) != 1)
        wasm_rt_trap(WASM_RT_TRAP_UNREACHABLE);
    return 0;
}
struct invocation {
    w2c_dmash__legacy__kyber module;
    struct w2c_a imports;
};
/* A C-only trap boundary; longjmp never crosses C++ secret-buffer destructors. */
int dmash_legacy_kyber_execute(int operation, const uint8_t *first, const uint8_t *second,
                               uint8_t *output1, uint8_t *output2) {
    struct invocation *call = calloc(1, sizeof(*call));
    if (!call)
        return -1;
    call->imports.module = &call->module;
    volatile int status = -1;
    if ((WASM_RT_SAVE_STACK_DEPTH(), WASM_RT_SETJMP(g_wasm_rt_jmp_buf)) == WASM_RT_TRAP_NONE) {
        wasm2c_dmash__legacy__kyber_instantiate(&call->module, &call->imports);
        w2c_dmash__legacy__kyber_d(&call->module);
        const u32 a = w2c_dmash__legacy__kyber_h(&call->module, 2400),
                  b = w2c_dmash__legacy__kyber_h(&call->module, 2400),
                  c = w2c_dmash__legacy__kyber_h(&call->module, 2400);
        if (!a || !b || !c)
            wasm_rt_trap(WASM_RT_TRAP_EXHAUSTION);
        if (operation == 0) {
            status = (int)w2c_dmash__legacy__kyber_e(&call->module, a, b);
            if (!status) {
                memcpy(output1, span(&call->imports, a, 1184), 1184);
                memcpy(output2, span(&call->imports, b, 2400), 2400);
            }
        } else if (operation == 1) {
            memcpy(span(&call->imports, c, 1184), first, 1184);
            status = (int)w2c_dmash__legacy__kyber_f(&call->module, a, b, c);
            if (!status) {
                memcpy(output1, span(&call->imports, a, 1088), 1088);
                memcpy(output2, span(&call->imports, b, 32), 32);
            }
        } else if (operation == 2) {
            memcpy(span(&call->imports, b, 1088), first, 1088);
            memcpy(span(&call->imports, c, 2400), second, 2400);
            status = (int)w2c_dmash__legacy__kyber_g(&call->module, a, b, c);
            if (!status)
                memcpy(output1, span(&call->imports, a, 32), 32);
        }
    } else {
        status = -1;
    }
    if (call->module.w2c_c.data) {
        OPENSSL_cleanse(call->module.w2c_c.data, (size_t)call->module.w2c_c.size);
        wasm_rt_free_memory(&call->module.w2c_c);
    }
    OPENSSL_cleanse(call, sizeof(*call));
    free(call);
    return status;
}

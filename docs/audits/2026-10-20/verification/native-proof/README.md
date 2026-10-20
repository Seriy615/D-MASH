# Bounded native QuickJS proof

Product baseline: `9446c22f27309131456942870971d477f6f2358f`, 20 October 2026 UTC. This directory preserves the **exact tested bytes** of the synthetic C embedding harness, generated JS source bundle and stdout. No compiled binary, QuickJS vendor archive, runtime storage, real identity, Account payload, credential or SDK state is included.

`source-load.js` is a self-contained 244,230-byte test artifact: a synthetic UTF-8/base64/random compatibility setup, **25 unchanged repository module bodies in original load order**, and six checks. It takes no repository argument and contains no dependency on the original `/tmp` path. It intentionally excludes browser `node_runtime_worker_v4.js` and the WASM Argon2 bundle. Source bodies were checked for exact byte inclusion and order against the baseline checkout. Original file licensing remains applicable; the embedded modules already belong to the public repository, including the existing TweetNaCl/BLAKE3 vendor sources.

The harness exposes OpenSSL `RAND_bytes` only; it does not supply the full WebCrypto API, browser APIs, networking, storage or Android lifecycle. Fixed Ed25519 test seed and Unicode test strings are synthetic. Recipient key material is random and exists only in process memory; stdout prints neither keys nor ciphertext. The test has no externally supplied code/data or network access. This small test-only harness has no production IPC/parser security claim.

## Reproduce outside the repository

Requirements: Linux C compiler, make, curl, tar with xz support, OpenSSL development headers/libcrypto. No Node.js, Python, Qt, Android SDK or real profiles are needed. Execute from this `native-proof` directory. The commands use a fresh temporary build directory and do not install system packages or change product source.

```bash
TASK_PROOF_BUILD=$(mktemp -d /tmp/dmash-native-proof.XXXXXX)
curl -fL --max-time 60 https://bellard.org/quickjs/quickjs-2026-06-04.tar.xz -o "$TASK_PROOF_BUILD/quickjs-2026-06-04.tar.xz"
(cd "$TASK_PROOF_BUILD" && echo 'b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a  quickjs-2026-06-04.tar.xz' | sha256sum -c -)
tar -xf "$TASK_PROOF_BUILD/quickjs-2026-06-04.tar.xz" -C "$TASK_PROOF_BUILD"
make -C "$TASK_PROOF_BUILD/quickjs-2026-06-04" -j2 libquickjs.a
gcc -O2 -I "$TASK_PROOF_BUILD/quickjs-2026-06-04" embed.c "$TASK_PROOF_BUILD/quickjs-2026-06-04/libquickjs.a" -lcrypto -lm -lpthread -ldl -o "$TASK_PROOF_BUILD/embed-proof"
"$TASK_PROOF_BUILD/embed-proof" source-load.js > "$TASK_PROOF_BUILD/proof-output.txt"
cmp proof-output.txt "$TASK_PROOF_BUILD/proof-output.txt"
sha256sum embed.c source-load.js proof-output.txt
```

The archive hash is the downloaded artifact hash recorded in this audit, not a claim of a separately verified upstream signature. Primary upstream: [QuickJS release](https://bellard.org/quickjs/), [embedding API](https://bellard.org/quickjs/quickjs.html). Memory limit is 128 MiB and stack limit 2 MiB; the C harness executes one synchronous bounded synthetic test bundle. Production event-loop scheduling, timeouts and interrupt handling remain implementation tasks.

## Results and provenance

Initial test files and executable: `/tmp/dmash-native-feasibility-20261020/{embed.c,source-load.js,embed-proof,proof-output.txt}`. Archive and `libquickjs.a` were built there. Copies here preserve the following hashes; original executable/archive were intentionally omitted.

| Audit file | SHA-256 |
|---|---|
| `embed.c` | `69ac81e5170bc0596008a3f321c5a26a2c090f456bfcbd3437672be6593b3ec9` |
| `source-load.js` | `02a3d52e9a18f8c9f970a498e56c71e2723e40d5c4affa34fc8dd0e89c18c932` |
| `proof-output.txt` | `5208f16b72a55a8fcbc9d875b2ea0488e4cec429b9b9fe9c34c8c961577bd8a9` |

**Initial compile/run PASS, exit 0. Audit-copy retest PASS, exit 0:** C recompiled from this directory into `/tmp/dmash-native-feasibility-20261020/portable-embed-proof`, executed the copied JS bundle, and `cmp` verified stdout identical to the preserved `proof-output.txt`. No tested proof source was edited for packaging.

```text
PASS UTF8 synthetic adapter
PASS unchanged TweetNaCl Ed25519
PASS unchanged resource SHA256 vector
PASS unchanged BLAKE3 vector
PASS unchanged recipient payload seal/open
PASS routing and ownership loaded
Loaded 25 unchanged source modules; NO transport/storage/Android PASS
```

The final check verifies exports, not every route state transition. Source loading and crypto examples do **not** establish complete JS/browser API parity, constant-time behavior, durable handoff, TLS/WSS, native UI, Qt linkage, APK/NDK build, Android sleep/reboot, NAT traversal or security completion. These gates are **NOT RUN** in this proof. The selected host and final UI boundary are specified in [NATIVE_HOST_FEASIBILITY.md](../NATIVE_HOST_FEASIBILITY.md).

## Embedded source manifest

Paths below are relative to `D-MASH PWA/not_messenger/js/` at the baseline SHA. These exact module bodies appear in `source-load.js` in this order; compatibility setup/checks are synthetic audit-only additions.

| Module | Original SHA-256 |
|---|---|
| `vendor/nacl-fast.min.js` | `3ec535c004aeeb225785d8e93fb33bf99f52e399bd7dfc01969b5629baea5131` |
| `vendor/blake3.min.js` | `8071ab35cb39002f3ba58c0b3ed48ce1be876d1c93a06a27572fe59d62afca0c` |
| `secure_session.js` | `757f002bedd54d7af8c88260b9c981d5234d9373f5af8e7a6d4a91c5b5c0c0a5` |
| `node_identity.js` | `47a18f80fd7e76b3bde39e0680830c8f317ab03eb0e282dddd32e26256560f43` |
| `node_relationships_v4.js` | `98c2889f0a915181d89dc0f36be2c236cd3b204346a11528587471ed5a677173` |
| `node_admission_v4.js` | `9c89e3aeba7c1e8ce8d99821ead92c43f1e59f083af7e73dacae5220f7705f50` |
| `node_registration_v4.js` | `674508bb0cf6f24e6a95bdee3cdb7b619af8c0c34ff12e9ed8474a029b9164d2` |
| `resource_pow.js` | `89a85384c71581d716c051fa5475ed01c7e3a761033e2cbd4fb7b6bd794ab81b` |
| `node_socket_v4.js` | `327eb904751b432c9035440e354be7f7a68c50033fed7858f26d684f7d58f106` |
| `node_channel_v4.js` | `75faf8dbe71754e30a50ba399a3a403e0cd1475886a02933ae63f2d5909e65f3` |
| `probe_primitives_v4.js` | `3cc1b7dbbb016258bb756279a7b2b18c907ef69849759b59c3fc021dee26011e` |
| `route_discovery_v4.js` | `60fcc805c8005b5b6bb28f0ecea84d0309980250ca2e502b771a64c5b2559248` |
| `recipient_payload_v4.js` | `8167b736b6a8e29c50ef8ffb146b0a712e3369cfa9895bdef171ff24b95e6a6a` |
| `node_routing_v4.js` | `9ae26919aed67ddadf62d681f9b398a2f51cbb4e54cc6fdd3244b4e0d320d900` |
| `node_inbox_v4.js` | `44d0271df2e831445db79692c8a2631d6f3a8aede7c3804b396faf1e7229524f` |
| `node_local_delivery_v4.js` | `8f610ac165381e34438cb4ff87daf8155ba96ff1e7c6a1a2cd09b66ff56de710` |
| `node_local_ownership_v4.js` | `c3ff0523f260fbeaa41ec973e6ad5ed94688dae6bb9ef628d4ca841ca3bf5464` |
| `account_pairing_v2.js` | `49692f34da52870e90d9f447ce8252afff40d82d972b238af3b5040e2a213a63` |
| `account_route_binding_v2.js` | `209f83e06cd6aa5439b23b627dcf534acb7abf1bd820334cf09bd737e58f312b` |
| `node_bootstrap_control_v4.js` | `c2f04dafebc3f93df8262edbb4c9e9a8bef665b1aa7f538ed651d7f63eee56f2` |
| `node_bootstrap_dispatcher_v4.js` | `2741afd5d220c9ca3f7e0154490600ec075dca5ee77fa77f14896ff988576a4b` |
| `node_bootstrap_runtime_v4.js` | `bb0e8aed378b6e91213989988989b4d392c4b57ee40d8d34ff8e64e934475592` |
| `node_public_bootstrap_control_v4.js` | `91f7cbef5df02e3449c8fbee99425afe68f4b4e8bb584c6d3e80a39f352387ad` |
| `node_public_bootstrap_runtime_v4.js` | `88d4a94bede1d265558bc27da61446c9988db8e87ae03b8d75f2eee0295dd290` |
| `node_service_descriptor_v4.js` | `e69d5c118de8c0b5bedda6b71b3ba2568d0b3b03aca4431b9f18fad54fabe68d` |

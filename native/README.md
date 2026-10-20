# Common native host (C01/C02, in progress)

Android, Linux and Windows share this production foundation. Account plaintext/E2EE and the credential broker remain outside the network process. This directory contains the actual headless Qt/QuickJS actor, compiled source allowlist, transport-only WebCrypto/timer/WebSocket/Worker adapters, strict scoped input and encrypted relationship persistence. The existing JS Node runtime has authenticated against the existing Python Node at default difficulty22 and exchanged the ordinary encrypted SERVICE_QUERY/SERVICE_UNAVAILABLE operation without Account. No usable native Node application or release acceptance is claimed yet.

The existing Node v4 JavaScript protocol modules remain the protocol implementation. Shared JS changes are an optional trusted native activation nonce-hash factory (browser fallback unchanged), and an optional trusted `store` adapter in `NodeRelationships.open`; its default IndexedDB path is preserved. Encryption, storage identity binding, directional relationship generation and validation remain in that existing module. The native SQLite adapter implements its atomic revision/null, empty binding/orphan and `maxRelationships + 1` count semantics. It accepts IV/ciphertext envelopes, never Account content or SQL supplied by an IPC caller.

`TransportBundle` is move-only, rejects unknown fields (including Root/PIN/Account material), bounds endpoint grants and validates their URL/Node ID syntax. Cryptographic Node identity work, endpoint pinning, secure-session admission/registration and replay checks must still run in the reused JS modules before any peer becomes authorized. Structural bundle validation alone grants no network authority. `clear()` wipes the bundle-owned byte arrays; it cannot wipe caller-owned QJson/QString copies of a parsed input. The local IPC layer caps frames before JSON parsing and retires its owned raw buffers; no complete process-memory erasure claim is made. Keys here are scoped Node transport keys; generations and direct policy do not change Node identity.

Build against the owned toolchain described in [TOOLCHAIN.md](../docs/native/2026-10-20/TOOLCHAIN.md):

```sh
export TC="$HOME/.cache/dmash-native-20261020"
export PATH="$TC/venv/bin:$PATH"
cmake -S native -B "$TC/build-native-linux" -G Ninja \
  -DCMAKE_PREFIX_PATH="$TC/Qt/6.12.0/gcc_64" \
  -DOPENSSL_INCLUDE_DIR="$TC/openssl-desktop/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$TC/openssl-desktop/lib/libcrypto.so" \
  -DCMAKE_BUILD_TYPE=Debug
cmake --build "$TC/build-native-linux" -j1
LD_LIBRARY_PATH="$TC/openssl-desktop/lib:$TC/Qt/6.12.0/gcc_64/lib" \
QT_PLUGIN_PATH="$TC/Qt/6.12.0/gcc_64/plugins" \
ctest --test-dir "$TC/build-native-linux" --output-on-failure
```

Tests use disposable synthetic data and independent SQL connections. Crypto vector tests cover SHA256, RFC4231 HMAC, RFC5869 HKDF and NIST AES128/AES256 GCM plus wrong key/AAD/tag rejection and bounds. Additional focused tests cover activation u64 nonce boundaries/padding, endpoint scheduling and timer adapter regressions. These do not establish complete WebCrypto API conformance, Android/Windows execution, physical power-loss durability or all Node transit/recovery acceptance. The actor now initializes the existing injectable JS NodeInbox against the separate [Inbox SQLite port](persistence/README.md), preserving atomic promotion, owner binding and bucket/usage quota semantics. It stores outer encrypted records; no Account/legacy key restoration runs. The native job adapter now persists opaque accepted jobs and schedules them through unchanged discovery, 500ms batching and recipient Inbox. Its executable Linux acceptance is described below; consumption intents and platform service hosts remain open.


The headless proof CLI accepts `--profile PRIVATE_DIRECTORY --bundle PRIVATE_FILE --service-query --run-for SECONDS`. Unix profile/input ownership and permissions are checked; a profile lock rejects another owner. Symlink/path checks provide best-effort protection and do not isolate a hostile same-UID process. Windows protected-storage ACL support fails closed pending implementation. Input is capped before JSON parsing, and the owned raw buffer is wiped on success/failure; caller JSON/string copies remain outside that guarantee. No Root, PIN, Account password or Account keys enter this actor. Endpoint attempts are limited to two, URLs for one Node identity run sequentially, and retries/backoff have bounded attempt counts. Password-protected peers currently fail closed: their browser Argon/WASM worker is deliberately absent; a later reviewed broker-issued endpoint Kpwd grant is required.

`python_interop_fixture.py` starts an unchanged localhost Python Node with default22 work and creates a temporary scoped broker fixture. Use the current patched test Python from the toolchain notes; keep the fixture running for retained-profile reopen tests. It accepts `status`/`stop` on stdin. Never publish its generated broker file or database. Protocol identity/admission checks are not bypassed. The actor computes work on at most two cancellable native worker threads, retaining the global slot until the worker actually exits. The trusted SHA256 prefix-state port preserves big-endian u64 transcript bytes; each factory checks nonce0, MAX_SAFE_INTEGER and u64 boundaries against the existing independent JS SHA before use. Decimal admission hashing remains unchanged and separate. `DMASH_NATIVE_BENCH=1` emits only timing and public proof metadata.

The inherited broker FD and scoped local IPC implement the first C02 service boundary. Full broker supervisor integration, consumption-intent recovery/events, complete route/transit fault recovery, Android service packaging/runtime and Windows runtime remain open. This is an integration checkpoint, not the finished application.


Actor SDK calls reject after close and initialize is one-shot. Queued reports carry an owner generation and are suppressed after close. The Unix CLI opens input with no-follow/nonblocking flags and validates the same descriptor with fstat before reading; a substituted FIFO/directory/symlink or broad-permission file is rejected. Focused lifecycle and descriptor-boundary tests supplement the actual Node exchange; they do not establish Windows ACL or Android process-service behavior.

Android ARM64 common actor compilation and optional JNI **link-only** probe can be reproduced with the same owned toolchain:

```sh
ANDROID_NDK_ROOT="$TC/sdk/ndk/27.2.12479018" \
"$TC/Qt/6.12.0/android_arm64_v8a/bin/qt-cmake" -S native \
  -B "$TC/build-native-android-arm64" -G Ninja \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-28 \
  -DANDROID_SDK_ROOT="$TC/sdk" -DQT_HOST_PATH="$TC/Qt/6.12.0/gcc_64" \
  -DOPENSSL_INCLUDE_DIR="$TC/openssl-android/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$TC/openssl-android/lib/libcrypto_3.so" \
  -DDMASH_QUICKJS_DIR="$TC/build/quickjs-2026-06-04" \
  -DDMASH_QUICKJS_LIBRARY="$TC/build-android-arm64-probe/libqjs.a" \
  -DBUILD_TESTING=OFF -DDMASH_BUILD_ANDROID_LINK_PROBE=ON
cmake --build "$TC/build-native-android-arm64" -j1
```

This produced an AArch64 shared library containing the real common actor and compiled JS modules, linked against Android Qt/Core/Network/WebSockets/Sql, renamed OpenSSL crypto and libc++; its three LOAD segments satisfy 16KiB alignment. [Public source hashes and linker evidence](tests/evidence/actor-android-link-20261020.json) record the exact result. No JNI invocation, Qt loader/APK packaging, Android service start or on-device transport test is claimed. The optional test JNI function accepts no credential or file-path arguments and is not the service/broker interface.


## Local service and opaque jobs (Linux checkpoint)

`--bootstrap-fd N` replaces `--bundle` for service mode. The inherited duplex AF_UNIX stream must authenticate the current UID. The broker sends one bounded `InstallTransportSession` frame with the strict transport bundle, explicit policy revision and bounded principal roles. After actor initialization, the daemon returns its private socket endpoint, owner epoch and fresh expiring256-bit capabilities only through that FD. The FD is a broker-service lifetime lease: UI socket closure does not revoke transport; broker EOF raises durable transport/policy floors, wipes/closes the actor and exits. Explicit broker `revoke` persists its floors before the local ACK. Verified stale bootstrap grants return key-authenticated minimum floors through the private FD before failure; a supervisor must verify owned-child exit before merging those floors into its own journal. No automatic reset/reseed is allowed.

The filesystem socket is owner-private, checks peer UID and requires the capability independently. Requests use bounded length prefixes and fatal UTF8 validation before parsing. Eight live clients, four pending requests per client/eight globally, frame deadlines, expiring scopes, request/byte rates and bounded output queues apply. Broker controls cannot read owner jobs or Inbox; an owner additionally proves the existing Account public signature challenge. Account signing remains outside the network process. That local proof authorizes a local scope; neither the route credential nor outer box by itself authenticates the sending Account on the mesh. Live policy/revoke uses the broker capability on the socket; bounded `MintCapability` frames on the inherited FD renew only configured principal roles, retire their old local contexts and return fresh tokens privately. Malformed control fails closed. The broker codec/journal library is not linked into the actor.

[LOCAL_IPC_V1.md](LOCAL_IPC_V1.md) defines the contract and remaining gates. The actor owns the encrypted [job ledger](JOB_LEDGER.md), managed local bindings and existing NodeInbox. A destination grant pins the certificate and ACTIVE reply authority. Acceptance commits its own opaque packet, scoped operation digest and quotas before replying. Fair bounded retry/discovery works after the UI disappears. Offline bootstrap waits use peer events/expiry; terminal retention cleanup participates in the same scheduler deadline rather than retaining quota forever. Native sidecar guards observe the unchanged channel's awaited batch completion, recheck current policy/attempt immediately before writes, and never add a mesh field or ACK. Success is only TRANSPORT_SENT; the existing ACK-free recipient-crash loss window remains.

`tests/local_ipc_test.py HOST SYNTHETIC_BUNDLE CACHE` exercises the real executable's capability/frame/role/lifetime/policy/floor/restart boundaries without dialing a peer. `tests/ipc_delivery_test.py HOST CACHE` starts an unchanged default22 Python transit and two actual native actors. Synthetic Account clients prove/install managed bindings outside the actors; a child UI submits an opaque box while policy blocks transport, is killed after acceptance, and the broker resumes transport. The fixture checks recipient Inbox, identical-submit conflict/dedupe, another operation carrying the same packet, and retained sender restart. Raw profiles, capabilities and keys stay in private temporary files/pipes and are not public evidence.

`inbox.list` returns bounded byte-paged opaque records. `inbox.commitConsumption` and resumable local application-commit intents, cursor events, complete supervisor recovery, physical crash/power-loss coverage and native platform services are not implemented by this checkpoint. Android/Windows delivery is NOT RUN. Linux local-socket permissions and same-UID checks do not isolate a compromised process with the same OS account.

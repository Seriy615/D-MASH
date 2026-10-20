# Isolated credential broker (S02 foundation)

`dmash_credential_broker` is a separate QtCore/QtSql/OpenSSL3.5.9 target. It must be linked only into the credential/UI owner process, never `dmash_native_actor` or its network host. Android uses a Java/Kotlin Views UI and separate credential/native service boundary; desktop uses a Qt Widgets UI/credential owner and separate user daemon. This directory implements the compatibility codec, persistent canonical credential store, worker service and public control journal; platform application processes and IPC server live outside this target.

`root_codec.h` exposes an in-process move-only prepared handle with public DeviceID only. `openExisting` requires an encrypted existing canonical Root row and a current-operation guard; empty/malformed/unknown profile and wrong PIN fail, with no storage or creation side effect. It accepts deployed v1 Argon2d first and an authenticated-only bounded Argon2id compatibility fallback. V2 is exact Argon2id19/type2/time3/65536KiB/p1/32B. Salt is **UTF8(base64(random16))**, matching the actual bundled JS, not raw salt. OpenSSL implements the standard primitives. Account password KDFs are not imported or changed.

`prepareRewrap` independently derives/opens the new wrap and compares the same Root before returning an encrypted candidate. All opaque metadata/material ciphertext is preserved. It intentionally does not advance revision, commit, publish, complete pending setup, migrate wipe verifiers or clean old databases. A native credential service must do those operations together through authoritative persistent CAS, with the S01 committed/cleanup-pending contract. Using this codec as a standalone credential-change UI would be incomplete.

DeviceID retains existing HKDF canonical u32-big-endian version/domain/context, zero32 salt, Ed25519/X25519 derivations and `dmash/device-id/v1` public digest. `existingTransportBundle` can decrypt only `node-ed25519-pow-v4` and `node-base-ncrh-v4`, plus derive existing `dmash/node-storage`, version4, `directional-relationships`. Pending/legacy/cleanup-required credential states cannot export a bundle. Missing slots fail; no new Node seed, pairwise device identity, random route ID or implicit replacement is invented. Endpoint structure is checked; Node work, existing grant signatures and peer authorization remain mandatory in the actor. The synthetic seed fixture is deliberately not mined and grants no network authorization.

The [local IPC contract](../LOCAL_IPC_V1.md) is a separate OS-authenticated capability boundary. Control/preauth frames are capped65536 bytes and authenticated data524288 before allocation/parsing, with existing smaller semantic limits. Broker control installs/revokes a scoped transport session or advances policy; it exposes no PIN/Root/Account/material-alias API to the daemon. Account logout/UI close leave approved Node transport alive. Explicit full Root lock revokes generation and closes transport keys/sockets, preserving ciphertext queues. OS-wrapped autonomous restart authority is a separate explicit policy; no full Root is persisted in a network bundle.

Secret buffers owned by the codec are cleansed on disposal/error. Caller PIN buffers, Qt string copies of transport bundles and provider/runtime internals cannot be erased by this class; the owning service/IPC layer must minimize copies and retire them. The current-operation guard checks before/after expensive operations; synchronous OpenSSL Argon2 is not interruptible mid-call. Run it off the UI thread, advance a monotonic owner epoch on cancel/lock and reject late completion. This codec is not a cross-thread session coordinator.

Build standalone with the owned Qt/OpenSSL toolchain:

```sh
cmake -S native/broker -B PRIVATE_BUILD -G Ninja \
  -DCMAKE_PREFIX_PATH=OWNED_QT \
  -DOPENSSL_INCLUDE_DIR=OWNED_OPENSSL/include \
  -DOPENSSL_CRYPTO_LIBRARY=OWNED_OPENSSL/lib/libcrypto.so
cmake --build PRIVATE_BUILD -j1
ctest --test-dir PRIVATE_BUILD --output-on-failure
```

The public synthetic fixture is generated with `node native/broker/tests/generate_compatibility.cjs /path/to/repo` by `tests/generate_compatibility.cjs` with actual existing JS DeviceRoot/Nacl/WebCrypto. CTest covers old d, old explicit-id, modern id, identity/material preservation, verified native rewrap, refusal/schema/cancel and fixed transport scope. Native→actual bundled-WASM reopen is a separate test script: run `dmash_broker_codec_test PRIVATE_SYNTHETIC_OUTPUT.json`, then `node native/broker/tests/reopen_native_wrap.cjs PRIVATE_SYNTHETIC_OUTPUT.json` with Node24.19.0. Neither is Android/Windows runtime, actual platform biometrics, complete browser-storage import, durable native credential migration or a usable app acceptance.

The [control lifetime contract](LIFECYCLE.md) and `control_journal.h` reserve durable generation/policy floors and pending full-lock state. They contain no Root/PIN/Account keys and do not claim another process has stopped.

Next integration: complete browser exporter and OS storage-key provisioning; OS-local UI/broker/daemon capability transport; actual desktop Widgets and Android Views/service lifetimes; separately authorized durable full-profile wipe coordinator. Fresh setup requires affirmative full-installation inventory, never inference from a missing Root.

## Persistent owner API

`credential_store.h` implements the canonical owner database, separate from the
network actor. A caller supplies an OS-protected 32-byte **credential storage**
key; it is not the Node storage key and never enters the daemon. SQLite uses
WAL/FULL and a singleton revision CAS. Root rows and the complete original
profile package are independently AES-256-GCM encrypted. Credential updates can
change only wrap/credential metadata; opaque materials and metadata are compared
and retained. A missing/corrupt store refuses unlock and never creates a Root.

`importProfile` requires a live proof for the exact encrypted Root and an explicit
complete exporter inventory: `{version:1, inventoryComplete:true, root,
databases:[{name,stores:[{name,records:[...]}]}], ancillary:{...}}`. The exporter
must include every database/store/record, including empty stores, Account keys,
history, ownership and relevant ancillary state. `inventoryComplete` is its
assertion, not a native scan or a browser-export implementation. The entire
package is retained byte-semantically as JSON, including unknown fields. Bounds:
256 databases, 100000 records, 64 MiB compact JSON. Oversize installations refuse
rather than silently truncate. A private, exclusive encrypted backup is written
before import acceptance; source storage is never deleted. `readProfileBackup`
authenticates that backup independently of the canonical SQLite file and can feed
an explicitly authorized restore/import to a **new** target. Partial failed
imports remain recognizable and are not interpreted as empty installations.
JSON exporters must preserve binary/key types explicitly (for example tagged
base64); this API cannot infer IndexedDB types from ordinary JSON.

`broker_service.h` owns Root handles and SQLite connections on one worker thread.
Its bounded queue returns futures, so Argon2 does not block the UI. `unlock`,
`change`, `resumeCleanup`, `transport`, `fullRootLock` and
`confirmTransportStopped` expose only public status and the strict existing Node
bundle. Cancel advances the operation epoch; a late KDF cannot publish a handle
or bundle. Argon2 itself finishes before its temporary secret is disposed.
`change` verifies the same Root, creates the exact JS wipe-verifier profile,
commits new credentials with cleanup-required, then invokes an owner callback
that removes **only** legacy `sys_m`/`sys_w` fast verifiers. Failure/cancel after
commit returns `committed:true`, the committed revision and `cleanupPending:true`;
retry uses the new master through `resumeCleanup`. Cleanup completion is another
CAS and never claims the cross-store operation is atomic. The callback must
report actual persisted cleanup and must not delete source Account/history.

The service lifetime must outlive UI windows and Account logout. These operations
do not call full Root lock. `transport` reserves the durable control generation; immediately before authenticated
handoff the owner must check `isCurrentTransportResult(result)`, so a previously
returned result cannot be installed after cancellation/full lock;
`fullRootLock` immediately fences broker completions and returns REVOKING floors.
The process supervisor still must send revoke and verify an authenticated exact
acknowledgement/owned-child exit before calling `confirmTransportStopped`.
A previous ACTIVE/REVOKING journal requires that recovery flow before a new grant;
no process-stop claim is inferred from SQLite. OS storage-key provisioning,
complete browser exporter, platform IPC and daemon supervisor integration remain
caller responsibilities.

The `broker-credential-service` CTest exercises actual encrypted import/backup
reopen, same opaque history, competing SQLite CAS, abrupt process exit after
commit/reopen, cancellation, committed cleanup failure/retry, legacy rewrap and
lock generation. These are native component gates, not browser or platform app
acceptance.

`BrokerService.importProfile(package,pin,backupPath)` now runs the explicit import
on its owner worker and retains the authenticated handle on success. Its
`committed` status distinguishes acceptance from a later cancellation.
`readAccountRegistry(encryptedRows)` is a separate **Account-owner-only** reader,
never a daemon method or transport-bundle field. It opens the existing
`account-registry-v1` Root material, authenticates deployed AES-GCM/AAD and HMAC
aliases, and returns registry records to the owning Account process without
exporting the registry key. Missing material never generates a replacement key.

The canonical credential row also records Account import publication:
`PENDING` permits authenticated initial-inventory resume; a typed
`PublishedAccountImport` from the opened published Account store acknowledges
`COMMITTED` and binds its canonical path. Old native stores migrate to
`UNVERIFIED`, which requires verification of an existing Account database and
never authorizes replay. Root mutation/CAS preserves this phase. The owner must
check the receipt against its configured database path before acknowledgement.

# C02 encrypted Node Inbox persistence

`InboxSqlStore` implements the existing
[NodeInboxV4 injectable store](../../D-MASH%20PWA/not_messenger/js/node_inbox_v4.js)
contract using SQLite. The unchanged JS owner encrypts/decrypts rows, authenticates
the installation owner and Account slot, and decides what receipts mean. C++ sees
only opaque encrypted envelopes. No Account plaintext, E2EE key, Root or PIN is an
adapter parameter. This is a persistence port, not a new wire/custody protocol.

The actor/platform dispatcher is integrated separately by its owner. This
checkpoint does not claim a complete native application, IPC security, real Node
network interop, Windows/Android runtime or power-loss acceptance.

## Bounded API and schema

Include `inbox_sql_store.h`, namespace `dmash`, target `dmash_native_inbox`.
Constructor `InboxSqlStore(file, maxRecords=4096, maxBytes=32*1024*1024)` opens a
unique same-thread Qt QSQLITE connection, requires WAL and `synchronous=FULL`, and
uses `node_inbox_rows`, `node_inbox_usage` and `node_inbox_meta` tables. It can share
the Node database with the separate relationship adapter; no global SQLite
user_version is changed. Unknown Inbox schema is refused rather than reset.

| Existing JS method | Native API | Contract |
| --- | --- | --- |
| open | Constructor; wrapper open returns itself | No plaintext ownership check inside C++; JS opens/verifies owner. |
| read(key) | optional EncryptedRow | owner, 64-hex record or binding:+64-hex key only. |
| all / allBindings | QVector EncryptedRow | Separate records/bindings snapshots; hard aggregate bounds before materializing blobs. |
| reconcile | void | Recomputes both usage buckets atomically from bounded actual SQL rows. No decrypt or owner reassignment. |
| cas(key,expected,row/null,{guard}) | bool cas(key,optional revision,optional EncryptedRow) | Exact expected revision, mutation and usage in one BEGIN IMMEDIATE transaction; stale returns false. |
| promote(source,sourceRev,target,targetRev,row/null) | bool promote(...) | Atomically checks both revisions, writes/replaces target if supplied, deletes source and updates records usage. Null replacement preserves an existing target's exact bytes/revision; missing target is an error. |
| close | void | Permanent close; same-thread lifetime fence rejects subsequent reads/writes. |

Envelope shape is the shared `EncryptedRow {QString key,qint64 revision,QByteArray
iv,ciphertext}`. Incoming write row key/revision are ignored; native assigns the
validated API key and incremented revision. IV must be 12 bytes and ciphertext
16..65,536 bytes. Revisions must be safe positive JS integers; incrementing
MAX_SAFE_INTEGER is rejected. Deleting a max-revision row is permitted.

Records quota is configurable 1..16,384 rows and 1 KiB..64 MiB, default 4,096/32 MiB.
Bindings have their original independent 33-row/256 KiB budget (owner plus up to 32
bindings). Charge is `ciphertext bytes + 128`, matching the original JS store.
An existing store above a newly lowered soft quota permits non-growing/shrinking
operations; growth beyond either effective quota is rejected. Persisted hard
bounds still apply before fetch, including on reopen. Usage must match actual SQL
aggregates before mutation; missing/inconsistent metadata fails rather than
silently admitting extra work. Explicit reconcile repairs valid bounded usage.

The owner insertion additionally checks **both** buckets are empty inside the
same write transaction. The original consumer already checks orphan records
before owner CAS, but its separate read/CAS leaves a race. This native guard
closes that gap and prevents assigning a new owner over existing encrypted rows.
Malformed native keys/envelopes/revisions also fail earlier than JS decryption.
Valid existing consumer behavior is preserved; no migration rewrites row crypto.

The JS wrapper must run its `guard()`/current actor check immediately before a
**synchronous** native mutation, without awaiting another task, and turn false
into rejection. C++ owns creating-thread/closed checks and transactions; it
cannot evaluate a JS closure. A new actor generation must not reuse a closed old
wrapper. Database path validation/private directory permissions and authenticated
IPC are caller/platform responsibilities, not furnished by this API.

There is no Inbox lease in the actual JS contract and none is invented here.
`NodeInboxV4.acknowledge` retains its existing pending→seen local transition after
Account persistence; promote can preserve that seen record so deferred retries
do not resurrect acknowledged data. Seen pruning still follows existing 30-day JS
policy. This is not eternal deduplication, a new remote ACK or provider custody.

## Tests and reproducible commands

Build as a standalone subproject without touching the actor's top-level CMake:

```sh
export TC="$HOME/.cache/dmash-native-20261020"
export PATH="$TC/venv/bin:$PATH"
cmake -S native/persistence -B "$TC/build-inbox" -G Ninja \
  -DCMAKE_PREFIX_PATH="$TC/Qt/6.12.0/gcc_64" -DCMAKE_BUILD_TYPE=Debug
cmake --build "$TC/build-inbox" -j2
export LD_LIBRARY_PATH="$TC/Qt/6.12.0/gcc_64/lib"
export QT_PLUGIN_PATH="$TC/Qt/6.12.0/gcc_64/plugins"
ctest --test-dir "$TC/build-inbox" --output-on-failure
NODE_PATH="$HOME/.cache/dmash-tools/js-tests-20261020/node_modules" \
  "$HOME/.cache/dmash-tools/node-v24.19.0-linux-x64/bin/node" \
  native/persistence/tests/node_inbox_sqlite.cjs "$TC/build-inbox/dmash_inbox_bridge"
```

Native test covers real SQL revision conflict, duplicate insert/delete, both
promotion modes, byte/count quotas, bindings separation, owner/orphan rejection,
two independent concurrent connections, lower-quota shrink, inconsistent usage,
unknown schema, oversized corrupt stored blob, creating thread and permanent
close. SQL triggers abort after the target write or during usage update and
prove full rollback. A separate child exits without destructors **inside actual
promote after target write**, and another exits after committed promote; reopen
verifies rows and exact usage are respectively old or new, never half-promoted.

The crash hook is compile-gated `DMASH_INBOX_FAULT_TESTS` and built only into a
separate fault-test library. The production `dmash_native_inbox` has neither hook
nor environmental fault trigger. These process-exit tests establish SQLite
transaction boundaries; they do not simulate sudden machine power failure,
filesystem corruption, hardware lying about fsync or malicious external SQL.

The synthetic CLI bridge is test-only, bounds requests, accepts no SQL and does
not define production IPC. The JS regression invokes the **unchanged** existing
NodeInboxV4/LocalDelivery classes with actual WebCrypto/NaCl and native SQLite:
deferred promotion, wrong slot/guard, reopen, seen-preserving replay, duplicate
insert, corrupt ciphertext isolation, binding restore and no frame plaintext in
SQL files. Its transport opens a native process per operation; actor threading
and native async cancellation are not established by that harness.

Finally 70 bounded stateful operations run against the actual original InboxStore
using fake-indexeddb and against native SQLite. Outcomes and both bucket contents
are compared after every operation. This is a differential test of the original
store, not a reimplementation used as its own oracle. The deterministic fault
tests supply concurrency/crash coverage that the differential sequence lacks.
Results, exact inputs and retained failed harness-attempt hashes are recorded in
[verification.json](verification.json). No production/user data is used.

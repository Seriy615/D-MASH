# Account owner runtime

This library belongs to the Account/UI credential process, outside the network
daemon. `legacy_kyber.h` provides the existing Account KEM as a shared portable
QtCore API. It does not receive a DeviceRoot, expose Account keys to the daemon,
change saved identities, or rename the existing KEM as ML-KEM.

`vendor/kyber.c` and `.h` are WABT1.0.34 `wasm2c` output for the **exact existing**
`js/vendor/kyber768.wasm`, SHA256
`e9b316e56f5d1eef1f44f28bca99bec16ec9cff69af4b17d318143512255b009`.
The generated C executes that compiled artifact's keypair/encapsulation/
decapsulation code. There is no replacement cryptographic implementation.
The unchanged artifact's licensing/provenance remains applicable to its
translation; the translation is not relicensed as MIT. The separate unmodified
WABT runtime is Apache-2.0, with its full license retained. Tool/package/source
and every vendored file hash are in `PROVENANCE.json`.

[WABT's wasm2c contract](https://github.com/WebAssembly/wabt/blob/1.0.34/wasm2c/README.md)
describes this generated C plus runtime arrangement. Reproduce with
`python3 native/account/regenerate_legacy_kyber.py --wasm2c /path/to/wasm2c`.
The original artifact hash and translator version must match. Ordinary native
builds need no WASM translator or online download. CMake refuses if the original
WASM changed without an explicit adapter regeneration/review.

The only host imports reproduce existing Emscripten semantics: heap growth
refuses OOM; RNG callback1476/signature `pi` fills bounded linear-memory bytes
using OpenSSL `RAND_bytes` in place of browser `crypto.getRandomValues`.
Memory is allocated with explicit bounds checks, without installing process
signal handlers. A C trap boundary does not jump across C++ destructors.
Operations serialize WABT runtime access, use fresh linear memory, and cleanse
its complete contents on success/error. The Account-facing `SecretBytes` is
move-only and cleans its buffer. Caller copies and crypto provider internals
remain the caller/provider's responsibility. Run operations on the Account
worker rather than the UI event thread.

Standalone build uses the same Qt6.12/OpenSSL3.5.9 toolchain as the broker.
Set `DMASH_ACCOUNT_TEST_NODE` to Node24.19.0 to enable actual original JS/WASM
cross-decapsulation CTest, in both directions and with keys from both engines.
Native tests additionally cover roundtrip, exact length refusal, legacy implicit
rejection, concurrent callers and secret disposal. These gates establish KEM
compatibility; the following Account facade and platform app acceptance have separate gates.

## Owning Account facade

`dmash_account_service` exposes the asynchronous `AccountService` DTO interface to
Qt Widgets and Android Views/JNI. Its worker runs only an allowlist of existing
Account modules in the pinned QuickJS engine. It does not embed the network
actor or launch a desktop Node helper. The SQLite adapter implements the narrow
`db.transaction`/request/complete/abort contract used by the existing session
store, authenticated history, outbox and Storage Saved methods. Each transaction
holds one actual SQLite transaction across its selected stores; writes complete
before JS `oncomplete`. Account rows remain their original encrypted blobs.

An explicit complete-package import retains the existing Account vault rows and
secure registry accounts/meta. When a source has `dm_registry_secure_v1`, its
SECURE mode is persisted; a missing/locked/corrupt reader never selects a legacy
plaintext registry. The owning UI first imports/unlocks through `BrokerService`,
then supplies `RegistryReader(rows)` using its `readAccountRegistry` future.
That broker operation opens only the existing Root-wrapped
`account-registry-v1` material, authenticates each AES-GCM row with the deployed
AAD and its HMAC alias, and returns Account registry records in owner memory.
The registry key stays inside the broker. No plaintext registry is written into
the Account SQLite file and no source database is deleted. Legacy-only imports
are read as that explicitly recorded schema.

Account login uses the exact deployed Argon2d128 profile (identity plus
`D_MASH_GAMMA_V1_STABLE` salt), preserving signing/box keys and checking both
against the saved registry before publishing the session. Contacts/history read
existing encrypted rows and preserve their original alias derivation, including
the effective legacy `Core.fastHash` conversion of typed arrays to comma-separated
strings. Saved Messages uses the real existing `Storage.saveMessageGamma` path,
commits encrypted rows with LOCAL state and supports idempotent caller operation
IDs. It has no daemon dependency. Logout/cancel closes the Account session;
Node transport remains a separate lifetime.

The remote path uses the existing signed route journal, sealed operation,
AccountSessionRuntimeV4, AppCipher, authenticated history and outbox. The transport
callback is scoped by local route and must bind each scope to its own authenticated
owner connection; it sends only public ownership proofs/scoped route material and
opaque prepared recipient boxes. `sync()` drains bounded owner Inbox pages and
commits consumption only after the existing Account runtime reports durable
processing. Missing route/preparation/session authority is an error or an honest
pending state. This code alone does not establish ordinary remote-contact/chat,
process lifecycle, Android/Windows runtime, or browser acceptance.

The retained Account CTest fixture is generated using actual bundled Argon2 WASM,
a secure-only registry and Root-wrapped registry key, preserving an original
Saved row. `dmash_account_private_probe PROFILE_JSON ACCESS_JSON NEW_PRIVATE_DIR`
provides the same owning-profile gate for private complete exports; input paths
are its only arguments. The access JSON fields are `current_master`, `account`
and `account_password`. It writes only new private target copies, stores the
random development credential key in that target, never prints credentials or
message text, verifies the same saved Account identity/history and source hash,
and writes a diagnostic Saved message only into the isolated native copy.
Development key files are not an OS-vault protection claim.

Initial import recovery uses one durable phase in the credential broker. A new
complete import starts `PENDING`; only that phase permits authenticated
`accountImportInventory()` to resume from the retained original package.
`AccountService::importProfile()` returns an optional typed `importProof` after
opening the fully published Account database. The owner verifies its configured
canonical database path and calls `BrokerService::confirmAccountImport(proof)`
before enabling Account login. This records `COMMITTED` and the accepted path.
Cancellation after publication retains the proof even if the result reports
`ACCOUNT_SESSION_CHANGED`; publication must not be treated as rolled back.

Account import builds and checkpoints a private same-directory SQLite staging
file, then publishes without replacing an existing target. An identical-source
retry opens the accepted database and preserves subsequent native writes;
a different inventory refuses. Abrupt termination can leave an orphan staging
file, which is never selected as accepted state or deleted as another owner's
file. Tests terminate actual child processes before/after stage commit and after
publication, then restart from the durable broker inventory.

`verifyPublishedImport()` opens an existing Account database and returns its
receipt without snapshot replay. Old broker databases migrate to `UNVERIFIED`;
only verification of their existing Account database can acknowledge them.
A missing/corrupt database after `COMMITTED` or `UNVERIFIED` requires recovery
of the accepted database/backup: the initial browser snapshot cannot silently
replace later native history. These checks cover initial import publication,
not every Node/Account recovery requirement.

# Current implementation delta — 20 October 2026

This document updates the **implementation state**, without modifying the frozen
[9446c22 audit](../../audits/2026-10-20/CURRENT_IMPLEMENTATION.md). The committed
checkpoint used here is `d123325`, including credential integration `d8eff7d`
and instruction/source-contract correction `3541458`. Concurrent uncommitted
native actor work is excluded. See the [current threat model](THREAT_MODEL.md)
for assets, trust boundaries, adversaries and residual risks.

**Android, Windows and Linux applications remain unfinished.** No deployment,
physical Android runtime, Windows runtime or complete native IPC acceptance is
claimed. All remaining implementation work in the frozen backlog stays open
unless a bounded checkpoint below explicitly supplies new evidence.

| Area | Change since audited source 9446 | Evidence and remaining scope |
| --- | --- | --- |
| UI composition | `591b93e`: explicit dependency registration/composition replaces the release-managed 120-second timer-expiry path. Late Core loading receives the same wrappers, with ordering/idempotence/retry checks. | [Readiness regression](UI_READINESS_REGRESSION.md): real early/late UI actions and unit RED/GREEN. Legacy standalone fallbacks and multiple wrappers still exist; this is not a complete portable SDK extraction. |
| UI inventory | 178 stable control classes inventoried, including conditional/absent controls and historical recovery provenance. | [Inventory](UI_CONTROL_INVENTORY.md), [QA matrix](BROWSER_QA_MATRIX.md). An inventory is not all-controls PASS; network/media/OS-dependent alternatives remain NOT RUN. |
| Biometric trigger setup | `ac54dbe`: accessible Cancel, failure return, valid trigger validation, stale completion guards. `3541458` fixes the final v54 instruction override. | [Cancel evidence](BIOMETRIC_SETUP_CANCEL.md), [root cancel retest](root-biometric-cancel.json) and [final instruction retest](root-biometric-instruction-retest.json). OS-prompt cancellation and rollback of a created OS credential are different operations. |
| Root/local credentials | Foundation `7d153b1`→`1853bb0`→`176ae36`, effective integration `d8eff7d`: versioned Argon2id root wrap, explicit legacy reader, dedicated worker, prepared handles, native IDB transaction CAS, shared Web Lock, lifecycle fencing, strict schema and durable wipe intent. | [Foundation review](S01_FOUNDATION_REVIEW.md), [integration review](S01_INTEGRATION_REVIEW.md). Browser caller paths are wired; hardware/SW-enabled/multi-platform and full crash matrix acceptance remain separate. |
| Fast verifiers | Effective loaded UI/Core/wrappers no longer authorize with sys_m/sys_w. Successful authenticated migration commits the same Root under the new profile, then removes legacy verifiers with retryable cleanup state. | [Retained migration](root-s01-retained-migration.json): same device, Account keys and original Saved row, no reset. Unmigrated profiles, old tabs and old backups are not retroactively changed. |
| Account compatibility | Core/v50 explicitly use deployed type 0 Argon2d for deterministic Account derivation; key slices and identities remain unchanged. Legacy installation Kyber material remains readable. | Real bundled vendor/profile tests and root retained Account login. This is deliberate compatibility, not a statement that all KDFs are now Argon2id or KEM conforms to standardized ML-KEM. |
| Credential cancellation | Calculator AC cancels active service/worker work; pre-commit cancellation cannot publish. Durable commits carry typed receipts when later cleanup/cancellation fails. Root lock clears current prepared handles and terminates Core state. | [Actual worker cancellation](root-s01-worker-cancel.json); independent race/CAS/schema tests. JS byte-array clearing does not prove all VM/OS copies erased. |
| HTTP and Python dependencies | `d123325`: patched compatible FastAPI/Starlette/multipart pins, exact transitive constraints and artifact-hashed Linux/Python3.12 lock; retired HTTP rejects before body receive; Origin POST bodies capped at 64 KiB before parsing/auth/state. | [S03 report](S03_DEPENDENCY_SECURITY.md): backend 303/Origin 22 PASS, root independently ran23 related tests, audit 29 components/0 known advisories. Transport deadlines, PHP, deployment and non-Linux packaging are separate. |
| Native shared foundation | Committed C++ transport-bundle validation, crypto primitives and encrypted SQLite relationship adapter with CAS/ownership checks. | [Root CTest evidence](root-native-port-verification.json), [native README](../../../native/README.md). Compiling ports and Android disposable packaging do not establish a usable daemon/UI app. QuickJS actor/IPC/network/runtime integration is still in progress. |

## What the delta does not implement

The default browser profile remains `legacy-migration`; managed-v4 remains
explicit opt-in. New local-credential protection does not change Node wire,
pairwise routing, Account ciphertext format, transport roles or the file
protocol. Directed route/QR/envelope facts from the frozen implementation map
continue to apply. In particular, two captured v3 contributions expose both
route-key directions; opening an outer envelope is not Account sender
authentication.

Managed-v4 supervision/reconnect, persistent Node network mailbox issuance and
replay ledger, durable accepted-job handoff/custody, ordinary Account migration,
multi-peer default provisioning and complete v4 media remain open. The existing
DNSS mailbox is still lease → awaited send → delete, without mandatory client
durable ACK. Device fallback/event ACK stores have their own contracts; neither
can be generalized into a new network custody guarantee.

FileVault/FileRuntime/FileChannel still form the existing Account-owned file
flow: 64 MiB upper bound, 32 KiB transport chunks, final integrity/onCommit checks,
whole-file memory costs and `resumable:false`. Proposed provider buffers,
locator generations, offline anchors and file custody remain design work.

The native target keeps a credential broker/Account actor outside the network
process and passes scoped transport materials, not Root/PIN/Account secrets.
The current browser shares one same-origin trust domain. Full process/IPC/OS
protection, OS-wrapped unattended transport restart, native Android Views and
Desktop Qt Widgets clients are not completed by these patches. Policy changes,
queued direct retries, NAT mobility, power-loss recovery and OS suspension each
need their own real acceptance.

## Verification interpretation

The frozen audit records a successful historical baseline runner. The recovered
source591 runner failed one old WebAuthn harness; test-only446 fixed that harness
and the original FAIL remains recorded. This delta does **not** assert a new
whole-project runner PASS. It combines exact scoped evidence: independent
readiness/BIO browser flows, root retained-profile migration/cancel flows,
foundation/integration suites,303 backend tests,22 Origin tests and native
foundation CTest. The linked artifacts specify source, environment and limits.

Production/real peers were not used by the new credential UI acceptance: only
the owning loopback origin was allowed and external HTTP/WS were blocked.
Consequently those results cannot establish positive network, phone NAT, call,
file or provider failover behavior. A working native application across all
three required platforms remains the active goal.

## Subsequent bounded checkpoints

The original map above remains pinned to d123325. These later changes extend it;
they do not retroactively broaden older evidence.

| Checkpoint | Implemented and checked | Remaining boundary |
| --- | --- | --- |
| C01 `f3a3dee`→`8bc67f0` | Headless Qt/QuickJS Linux actor executes compiled existing Node modules, scoped crypto/storage/network ports and bounded compute workers; author actual default-work22 authenticated Node→Python SERVICE_QUERY/reopen; root [retained-profile two-process interop](root-native-actor-interop.json) independently verifies f3, owner rejection and SIGTERM/SIGINT exit0. Independent review found post-close/queued-report and duplicate-init defects; corrective guards/generation/one-shot initialization plus descriptor-bound Unix bundle validation now pass independent 6 CTest, two JS fixtures and actual CLI rejection checks. | [Independent review](C01_INDEPENDENT_REVIEW.md) attributes execution separately. No full route→Inbox→Account flow, authenticated IPC/service/UI product, private-password peer or Windows/physical Android runtime acceptance. |
| C02 `d81d356` + actor glue `8bc67f0` | SQLite encrypted Inbox port preserves separate records/bindings and usage; atomic CAS/promote, quota checks, owner/orphan rejection, rollback and process-exit recovery. Existing unmodified NodeInboxV4/LocalDelivery consumers and 70 stateful operations differential against original IDB store pass. Actor initializes encrypted Inbox owner using the scoped transport storage key. | [Port contract/evidence](../../../native/persistence/README.md). This adds persistence, not new remote ACK/custody/offline file semantics. Network-to-local delivery ownership acceptance remains open. |
| NODE-URL-XSS-01 `690cb1b` | Persisted Node URL and UI action arguments are handled as data rather than embedded JavaScript source. Root's [same-profile stored-data browser retest](root-node-url-xss-green.json) passes selection/removal, preserves identities/Root wrap/Saved row/QuickName/route, 107 exact source responses and zero page errors. | Fix is scoped to the corrected data/action sinks. It does not establish safety of every DOM/template path. The [original RED](root-node-url-xss-red.json) is retained. |
| MODAL-TITLE-XSS-01 `a22b2db` | Root-confirmed source finding: decrypted peer alias reached incoming-call modal title; peer rename/delete text also reached raw prompt/confirm text. Source now treats helper titles/messages and prompt values as plain text. | Author [scoped browser evidence](MODAL_TEXT_RETEST.md) confirms literal hostile alias in rename/delete/cancel flows; incoming-call title remains SOURCE/UNIT, NOT RUN in browser. Explicit openModal HTML-body templates still require caller-specific review. |
| S07 PHP `0645ec3` | Both unsupported PHP relay/webhook endpoints now return constant 410 before application input/parse/DB/provider/log access. Actual isolated PHP RED confirms own-key wrong-alias ciphertext read+delete, unsigned bindings and HTTP-readable exception log; eight regression methods now PASS. | [S07 inventory/proof](S07_PUBLIC_SURFACES.md). Signed Node/Origin unchanged. SAPI/HTTP startup buffering, deployment/historical logs and explicit legacy JS false-SENT caller handling remain separate open work. |

SQLite row encryption remains owned by the existing JS Inbox. The SQLite file
does not use whole-database encryption: table shape, blinded row keys, revisions,
IVs and usage/size metadata remain visible. 128 MiB QuickJS is a per-engine limit;
Qt/native allocations and up to two compute engines add process memory.

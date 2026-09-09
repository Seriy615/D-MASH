# Active transport-v3 work — 2026-09-09

Checkout: `/Users/afsvu/Documents/Codex/D-MASH/D-MASH`; branch `transport-v3`.
The earlier checkpoint is preserved in HANDOFF_TRANSPORT_V3.md. The current
transport semantics are specified and tested in TRANSPORT_V3.md.

## Hop-label foundation added after batching correction

HopRoutes stores peer/role-scoped random labels behind fresh HMAC indexes and
SecretBox-encrypted, bounded, expiring runtime records. Local NCRH mappings are
encrypted and never used as authority. HOP_DATA_V3 is wired through NodeChannel,
transport admission, snapshot-time route resolution and existing peer workers;
labels change at each hop while Device ciphertext stays opaque. Shutdown drops
the table's keys and rows. No raw RouteID persistence was introduced.

Six focused tests include a three-Node data path and revoked-before-flush
rejection. Bindings are explicitly installed in that fixture. Production Probe
still needs to install these mappings and return Device L0; old discovery's
global NCRH also still needs replacement. Do not claim milestone F complete.

## Current batching correction

The periodic tact loop has been replaced by first-arrival-armed one-shot
aggregation. IDLE has no timer. First arrival arms deadline = now + 500 ms;
later packets never move it. At deadline the incoming queue is synchronously
swapped out and returns to IDLE. A packet after that swap starts a separate
500 ms window immediately, independent of previous routing/sends. A late
callback cannot absorb arrivals belonging to the next window.

Closed snapshots resolve current blind local routing state, group by current
next-hop (different final recipients can share one batch), then split each
group into nonempty batches of <=128 packets and <=512 KiB canonical packet
array bytes. Independent FIFO send workers prevent a slow peer from delaying
future windows or other peers. Missing routes stay pending; stale enqueue-time
next-hop hints are not used for DATA. Local routes use existing mailbox checks.

Failures/cancellation retain unsent work; partial broadcasts retry only failed
peers. The global RAM queue budget includes snapshots and in-flight packets.
Retries are work-triggered and separate from aggregation; no periodic global
tact, padding, cover traffic or empty batches. Authentication, DNSS/resource
PoW and keepalive remain immediate. No persistent raw RouteID storage added.
Shutdown cancels workers before DB closure; same-engine restart retains RAM
work. This does not add process-crash persistence or remote receipt ACKs.
Historical supported outbox rows join the pipeline from a startup scan and
are deleted only after successful sends; unsupported rows stay preserved.

## Implemented foundation and remaining scope

Shared Python/JS secure sessions, mutual Node authentication and directional
DNSS work, resource authority, durable DNSS mailbox, Device Envelope/Inbox,
blind Account-route aliases, private route capabilities and Account dispatch
are implemented. ACCEPT/CONFIRM bootstrap is now wired with encrypted stored
transitions and Account-scoped import. Native Chrome localhost Inbox QA is
historical module evidence, not production acceptance.

Still remaining: hop-local labels/local NCRH, remote acceptance ACKs and
crash-safe transport recovery, legacy mailbox migration, password Node,
S-TURN/calls/files, epoch ratchet and full multi-node/browser acceptance.
Historical decrypt's ambiguous null result still leaves control packets pending.

## Validation and revision

Full run: `/tmp/dmash-v3-py312/bin/python tools/test_all.py`.
Final result: **161 backend tests, 11 Origin tests and 33 PWA suites passed**
(exit 0). This includes 21 focused aggregation/batch tests. Focused tests prove
P1-P4 at 0/120/340/499 ms close at 500 ms, P5 at 510 ms closes at 1010 ms,
next-hop regrouping, independent slow peers, exact batch limits, failure and
cancellation retention. Real authenticated Node WebSocket coverage exercises
the production aggregation window; all existing PWA suites remain required.

Implementation checkpoint: `0ebc49ab3d796b16f3817773f3885e1286c816da`.
Batching validation/documentation checkpoint: `c9fe8938c313f815602a1aff76434548f834f060`.
The current continuation adds the hop-label data-plane foundation above. No deploy or push is part of this fix.

## Historical handoff (retained verbatim below)

# D-MASH — Current Engineering Handoff

**Updated:** 2026-09-04 UTC  
**Chosen handoff:** `CURRENT_HANDOFF.md` (the active, repository-specific handoff; `LAST_HANDOFF.md` is historical routing/device architecture context).  
**Repository:** `/home/jcode/D-MASH` on `main`  
**Working-tree safety:** the tree is broad and dirty (including pre-existing/parallel work). Do not reset, broadly stage, or overwrite unrelated changes.

## Committed this session

- `3c03e8b` — **Add isolated contact transport boundary**
  - Adds `not_messenger/js/contact_transport.js` and its executable test.
  - This is an isolated boundary; it is **not** a claim that the full contact transport/e2e flow is complete.
- `6f1dd9a` — **Fix private route lifecycle reconnect races**
  - Updates private-route lifecycle/reconnect behavior in `core_engine.js` and `node_manager.js`, with `private_route_lifecycle.test.js` coverage.

## Uncommitted, fully tested work — do not casually partition

Device-level WebAuthn PRF / biometric unlock and device-level **Global Settings** are implemented in the current working tree, including focused executable PWA tests:

- `account_biometric_security.test.js`
- `biometric_account_login_disabled.test.js`
- `device_biometric_unlock_integration.test.js`
- `global_settings_ui.test.js`
- updated `device_root.test.js`

The implementation touches overlapping large hunks in `core_engine.js`, `device_root.js`, and `ui_logic.js` (and related PWA files). It was deliberately left **uncommitted** because safe hunk-level partitioning from unrelated dirty changes could not be guaranteed. Do not use a blanket `git add`; review and stage only after an explicit dependency/ownership audit.

## Validation completed in this session

- Full backend suite with `.venv-m1`: **88 passed**.
- Full PWA executable test suite: **17 suites passed**.
- The above includes the WebAuthn/device-biometric/Global Settings coverage and the current legacy guards.

## PoW and replay posture

Resource-PoW enforcement is fail-closed for new resource registration/activation paths: an absent, malformed, expired, wrong-context, or replayed proof is rejected. Replay tracking consumes an accepted proof so it cannot be used again; proofs are bound to the intended node/resource/device context. Existing normal data-plane operations (DATA, ACK, PULL, reconnect/probe, and repeat valid registration) are not assigned PoW merely for retransmission. Preserve this distinction when changing gateway or registry code.

## Legacy / privacy evidence and limitations

Legacy tests/import-compatibility evidence is present in the current tree, including `test_legacy_relay_disabled.py`, `test_legacy_privacy_guard.py`, `test_registration_lifecycle.py`, and compatibility handling in the registry/import paths. These establish the tested guardrails, not completion of a legacy migration.

Do **not** overclaim node-storage privacy or legacy removal:

- legacy API/P2P persistence and migration/removal still need a controlled audit and migration plan;
- browser acceptance has not been completed (the executable PWA suite is not a substitute for real browser/WebAuthn acceptance);
- no production deployment or real multi-device/browser acceptance is implied by the source tests;
- contact transport remains an isolated committed boundary, not a completed end-to-end contact workflow.

## Next work

1. Run direct browser acceptance for device biometric enrollment/unlock, PRF availability/failure paths, Global Settings navigation, and private-route reconnect behavior.
2. Before committing the uncommitted WebAuthn/Global Settings work, separately audit every dirty hunk and its dependencies; avoid unsafe hunk partitioning.
3. Define and execute a backed-up, controlled legacy migration/removal plan; retain the legacy privacy/relay guards until the replacement path is proven.
4. Do not deploy or promote solely based on these source-suite results.

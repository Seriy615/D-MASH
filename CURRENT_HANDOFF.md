# Active transport-v3 work — 2026-09-09

## Current recovery implementation

Authenticated recovery is wired end to end: each connection advertises RootNCRH
and eligible routes, tracks exact peer/request/NCRH statuses, and issues fresh
peer-owned labels after semantic replies. The receiver binds the label to the
advertised incoming prefix, not its own extended NCRH. The old reflected
`recover_alias` helper is removed. Root-only knowledge never grants DATA authority.

KNOWN/UNKNOWN describes knowledge before processing the current advertisement.
Hop-limit, loop/metric termination and capacity failure do not suppress status.
The graph and outward peer knowledge are encrypted, bounded and expiring RAM
state. Same peer/input NCRH is one logical candidate despite label replacement;
multiple prefixes and fork peers remain distinct. Independent peer export workers
and bounded timeouts isolate slow branches. Reconnection invalidates old handshake
grants before reading the new channel. Device label caching tracks remote label
changes. See TRANSPORT_V3.md for exact schemas, direction and lifecycle.

## Acceptance coverage

`test_recovery_protocol.py` uses four real authenticated NodeChannel/WebSocket
Nodes, with only expensive PoW fixture cost reduced. No forwarding table is
manually populated. An authorized initiator advertises to a middle Node and a
fork. The middle Node loses all runtime tables; its signing identity and BaseNCRH
are reused with a fresh RAM salt. Reconnection reconstructs the same logical
prefixes, replaces labels and delivers opaque HOP_DATA to the original mailbox.
Both fork peers receive the same prefix. Every observed advertisement has a
correlated semantic response; binds follow statuses and never authorize a Root.
A second real-channel test blocks one peer while another becomes ready, and
rejects a late reply after a forced semantic timeout.

Focused unit tests cover graph bounds/encryption/expiry, pre-advertisement status,
terminal responses, capacity failure, same-peer path alternatives, label refresh,
wrong-peer/wrong-NCRH/replayed/expired bindings and reflection rejection.
Existing tests also verify persistent BaseNCRH, corrupt-file fail-closed behavior,
fresh startup salt, encrypted backup contents and restore permissions.

Full validation command: `/tmp/dmash-v3-py312/bin/python tools/test_all.py`.
Final results: 184 backend tests, 11 Origin tests and 33 PWA suites passed
(exit 0), log `/tmp/dmash-recovery-final.log`. No deployment.

## Remaining broader plan

This checkpoint addresses authenticated route reconstruction and alias recovery.
It does not complete the original overall product plan. Remaining work includes
production PWA Probe orchestration across all route producers, durable transport
ACK/recovery, legacy mailbox migration, password Node access, S-TURN/calls/files,
epoch ratchet and complete browser/product acceptance. Existing backup restoration
stages and rolls back two secret files on replacement errors; it is not an atomic
two-file transaction across power loss. Node-only NCRH knowledge cannot recreate
Device mailbox ownership without the existing Device authority flow.

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

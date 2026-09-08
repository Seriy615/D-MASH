# Active transport-v3 work — 2026-09-08

Checkout: `/Users/afsvu/Documents/Codex/D-MASH/D-MASH`; branch `transport-v3`.
Started from clean `main` at `703a5df`. See `TRANSPORT_V3.md` for current
executable inventory, wire details, migration boundaries and test evidence.

IMPLEMENTED: shared Python/JS secure sessions; mutual Node peering and
directional DNSS work; v3 backend DNSS/resource authority and leased durable
mailbox drain. Device Envelope and encrypted Inbox modules pass real-crypto
multi-account tests. JavaScript DeviceClientV3 interoperates with the Python
gateway over a real loopback WebSocket. DeviceAuthorityV3 implements stable
DNSS rebind/re-registration and session-bound route signing. Mailbox insertion
rechecks live route authority. All 134 Node tests, 11 Origin tests and
28 PWA suites pass. Native Chrome localhost Inbox acceptance also passes;
this is isolated module QA, not deployed PWA acceptance.

PARTIAL: NodeManager now connects using v3, binds DNSS, registers public routes
with signed authority, wraps outgoing public contact requests in Device
Envelope and drains the whole DNSS mailbox into encrypted local staging.
Core delegates v3 polling to Device Inbox independently of locator handles.
The real loopback JS/Python test now exercises NodeManager itself.
Do not deploy this checkpoint: private route derivation and the Account
receive/send adapters are still pending, and peers require coordinated v3
upgrade. Legacy mailbox rows are preserved but not migrated. Device Envelope /
Inbox still need main PWA integration. Hop labels, batching, password,
S-TURN/calls/files and ratchet still need
implementation/integration and acceptance. No push, deployment or production
Chrome acceptance has occurred.

Next: finish private-route capability derivation and Account Inbox handler;
complete contact Accept/Account bootstrap. Preserve old tests and data.

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

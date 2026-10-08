# Ordinary Node UI integration audit — 2026-10-08

Review-only integration base: a75fb84 (.34 product plus documentation).
Frozen N4 dependency: e64747f, merged as an explicit parent; it contains code and
historical evidence, not a new acceptance result for this integration tree.
UI port: 120ad3f + 5544c8f. This branch is not deployed.

## Conflicts and preserved behavior

N4 dependency merge had no conflicts. Porting the previous UI seam conflicted
only in release.js/sw.js identifiers. Both remain
`transport-v3-node-preparation-20261008.34` for review; root must assign a new
release before publication. Browser evidence must therefore compare loaded bytes,
not identify this candidate by the release string alone.

Core delta is 48 added lines for captured Account adapter lifecycle. Existing
.34 Account deletion refusal, .33 media loader/video and recorded-note Account
cleanup remain. Node-owned transit is not closed on Account logout. Root lock
still closes runtime. Worker CONNECT reuse is included; discovery reprobe and
owner cancellation are separate reviewed commits and not included here yet.

## Security and integration findings

* Account adapter requires a committed captured session, matching vault/master
  key/root, managed Host and public-v1 profile. Keys are not regenerated during
  restoration. Bilateral public control and genuine owner/journal activation
  precede N4; ACTIVE alone cannot enable SEND.
* Fixed a missing integration seam: History now verifies successor proofs through
  the captured live Runtime; Runtime receives the trusted history migration and
  delivered-status verifier callbacks. These retain sequence/text/operation ID
  across authenticated rekey and permit safe retirement after a durable delivery
  commit. The construction test verifies callback binding and stale Account
  refusal; cryptographic/CAS guarantees are covered separately by N4/history tests.
* SEND requires `durableApplicationEnqueue`, then clears draft only on durable
  local history. queued:false is WAITING, not a failure; only authenticated receipt
  changes history to DELIVERED. No legacy encrypt/outbox/media path is used for a
  NODE_ACCOUNT_V4 contact. Legacy contacts retain their explicit old profile.
* Saved Messages has a non-wire local identifier and retains the existing local
  Account storage path. It must never acquire a peer route; component coverage
  verifies dispatch preservation, but current-tree full-shell proof is pending.
* Migration retains the pinned Account signing ID, requires confirmed N4 and a
  genuine active binding, asks explicit UI confirmation, then CAS-updates contact
  plus encrypted migration receipt. Old history/secrets and the previous encrypted
  contact are preserved. A changed Account ID is not an in-place migration.
* Public intake belongs to the root, independent of Account login. Claim/signing
  and Account publication require a captured Account. Retained signed intent can
  replay advance after an ACTIVE-before-index crash. Missing material remains
  PENDING; there is no identity reset or fabricated owner.
* Voice/circle/file/call are deliberately refused and hidden for managed contacts
  until authenticated CONTROL is available. This is a safety checkpoint, not an
  acceptable final text-only cutover.

## Open release gates

1. Root unlock still invokes the legacy NodeManager lifecycle. The managed pinned
   Node starts from the explicit Node UI/coordinator path; automatic root-owned
   startup and full removal of the migration gateway need a reviewed transition.
2. Existing PRIVATE QR/legacy public UI paths are not a complete managed private
   pairing replacement. Ordinary fresh and existing-contact migration must be
   exercised end-to-end using real controls and authenticated same-ID proof.
3. N4 e64747f still awaits network flush in receive; stalled discovery can delay
   Inbox ACK/progress. Local enqueue is independent, but the full offline/rejoin,
   stale ACK, rekey-pending and restart fault matrix remains a browser gate.
4. Expired committed routes are not restored through archive-only ownership in
   this orchestrator yet. Data remains intact, but read/drain and renewal require
   explicit implementation; do not silently mint a new certificate or drop rows.
5. CONTROL crypto/outbox/runtime is not available. Schema/dispatcher/service are
   separate inactive slices. Healthy authenticated same-channel service selection,
   ordinary S-TURN voice/circle/file/call, final durable receipt and failure UX are
   mandatory N3/N7 gates. No static URL or v3 STATUS fallback.
6. Migration currently rechecks N4 proof before its contact transaction; unlike
   pending-message successor migration, it does not CAS the three SessionStore rows
   within that transaction. Review the interleaved rekey case before production.
7. Full exact-source tests, real two-party UI including preserved legacy history,
   root-only transit, page/SW upgrade and deployed byte verification remain pending.

Validation on this integration source: 13 targeted UNIT suites PASS (history
WebCrypto/IDB emulator; orchestrator wiring/scheduling/guards/Core; UI/history
refresh/catalog; CONNECT reuse; N4 runtime/successor/outbox; media loader).
No Chromium, real profiles, backend, keys, DB or production changes in this audit.

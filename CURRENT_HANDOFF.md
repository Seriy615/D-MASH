# Execution update — 2026-09-25

Authorization now explicitly includes continued development through the entire
plan, commit/push, deployment for testing and EMS repository synchronization.

- `1c7a1154e3281b55883167eaafae379f96ae7099` is pushed to `origin/transport-v3`.
  `/home/jcode/D-MASH` on EMS was moved from old detached `5dbda4a` to tracking
  `transport-v3` at this SHA without touching untracked `tools/get_commit.sh`
  or `tools/deploy-ems.sh`.
- The required `get_commit.sh` initially failed on the root-owned lock file.
  The same script succeeded with its documented sudo invocation. It deploys
  **PWA only**, explicitly excluding Node runtime. Backup:
  `/srv/messenger.d-mash.ru/backups/manual-rollback-20260925T114654Z`.
- Published `release.js`, `sw.js`, `device_inbox.js` bytes match that commit;
  release is `transport-v3-n0-20260925.9`. Script's old release-name regex printed
  `unknown`; byte verification establishes the real release instead.
- Real Chromium two-account private-pairing acceptance PASS: authenticated
  registration, initial exchange, bidirectional messages, two ratchet epochs,
  delayed prior-epoch message, reconnect/queued delivery and retired handshake
  controls. Log `/tmp/dmash-ems-n0-two-accounts.log` (local test-only accounts).
  This remains v3 browser evidence, not v4 transit or TURN acceptance.
- EMS Node service is active but backend code was not updated by get_commit.sh.
  Node deployment needs a separately verified backend path; do not attribute the
  local legacy HTTP fix to production yet.

Current local continuation: H4 explicit-peer recovery and R1/R2 ratchet collision,
serialization and persist-before-ACK corrections, with version-2 control suites
and mixed-version refusal. See TRANSPORT_V4.md for the exact delta. Targeted tests
pass. H1-H3 are reproducibly FAIL with real bundled crypto in
`node tools/diagnose_initial_handshake.cjs`; their replacement state machine is
next. This is an ongoing checkpoint, not completion of N0–N8.

---

# Current checkpoint — unified Node N0, 2026-09-25

Base and fetched `origin/transport-v3`: `aa0ad8aac716570bf9b65b8901e4548c255251f3`.
This checkpoint is prepared for commit/push and EMS verification; see subsequent
execution entries for exact deployed evidence.
The user-provided `D-MASH_Codex_Development_Plan.md` is the controlling plan;
its original contents have been preserved. Older entries below are historical.

## Changes and evidence

- `TRANSPORT_V4.md` records the proposed versioned NODE-only contract,
  directional stable DNSS, separate admission/resource grants, common
  forwarding/store queues, privacy audit and migration gates. It explicitly
  leaves the Probe/authority redesign and browser fingerprint boundary open.
  No v4 endpoint, role change or browser transit is claimed.
- The legacy HTTP router now rejects requests with 410 before runtime state,
  key derivation, persistence or peer dialing. Regression tests cover 13
  endpoints plus bogus credentials/loopback headers. Before the guard, the
  tests produced 13 assertion failures. Both runtime entrypoints mount this
  same router. Public nginx exposure was NOT inspected; server deployment
  remains unchanged. The old server-hosted HTTP Account UI is retired.
- I1 reproduced with a failing first Account callback and a valid next record.
  Pending and staged Inbox drains now isolate per-record decrypt/handler errors,
  retain failed ciphertext, continue valid records, and abort on root lock/change.
  Tests use actual NaCl envelopes and AES-GCM storage with memory-backed IO;
  they cover tampering, retry, dedupe and mid-callback lock. This is UNIT evidence,
  not IndexedDB/browser acceptance. Durable quarantine/backoff and crash-after-
  Account-persist idempotency remain unfinished.
- Removed the tracked BaseNCRH sidecar from the working tree/distribution, with
  a private local backup outside the repository. Added secret-sidecar ignore
  rules. The lifecycle test was also creating/loading this default runtime
  secret; it now uses explicit test material. No deployed usage or rotation is
  established. Git history is unchanged; historical exposure remains.
- `requirements-test.txt` includes runtime requirements plus `httpx==0.27.2`.
  The pre-existing `/tmp/dmash-v3-py312` environment lacked required libraries;
  the initial test run failed on imports. Reference verification uses a fresh
  repository `.venv`, Python 3.12.14 and Node 24.19.0.

Validation command: `.venv/bin/python tools/test_all.py`.
Local result: **211 backend tests, 11 Origin tests, 49 PWA JS suites PASS**.
Regression failure log: `/tmp/dmash-n0-http-before.log`; full verification:
`/tmp/dmash-n0-final.log`. `git diff --check` passes. No crypto authentication,
PoW threshold, route ownership check or mailbox ACK semantics were weakened.

## Current milestone table

| Stage | Status | Evidence / remaining gate |
|---|---|---|
| N0 | PARTIAL | Source contract/privacy audit, HTTP and I1 regressions/fixes. H1-H4/R1-R2 regressions and privacy-safe Probe authority/metric design still open. |
| N1 | PLANNED | JS NODE peer, v4 wire/interoperability, general admission and stable directional DNSS not implemented. |
| N2 | PLANNED | No N1 -> browser -> N2 transit evidence; no Account-independent browser Node runtime. |
| N3 | PARTIAL (v3 foundation) | Multi-Account encrypted Inbox exists; unified Node integration/migration pending. |
| N4 | PARTIAL | I1 isolation corrected; initial handshake collision/recovery and ratchet collision/durable ACK remain. |
| N5 | PARTIAL | Legacy HTTP disabled locally, source sidecar removed. Deployed inventory/rotation, verifier migration, crypto/PFS/PCS review remain. |
| N6 | PARTIAL (v3 foundation) | General Node password gate, descriptor and installer migration remain. |
| N7 | PARTIAL (v3 foundation) | Existing signaling/call/file code; real TURN relay, unified admission and media acceptance NOT RUN. |
| N8 | NOT RUN | Local unit/ASGI/interop suites pass; v4 browser/transit, migration, production acceptance and release remain. |
| A-M / E6 | INCOMPLETE | Existing A-K transport/storage/media foundations are v3-specific; L reliability/security and M full acceptance are incomplete. E6 protected-history threat model remains separate. |

## Next implementation work

1. Close N0 Probe/root/origin-tag/metric/grant semantics against the external-peer
   observer model. Current `metric`, `trace.length`, global origin tags and
   endpoint-only operations are explicit blockers, not anonymity guarantees.
2. Add real-crypto failing H1-H4 and R1-R2 regression fixtures before moving
   Account state. Do not grow the acceptance monkey-patch chain.
3. Implement shared v4 Node handshake/admission/authorization, then browser
   transit through two authenticated neighbors without Account login. Follow
   the plan's N1/N2 no-bypass test before declaring the unified model ready.
4. Before any release, inventory existing BaseNCRH usage without exporting
   secrets, back up and rotate affected runtime state with recovery/re-advertising;
   verify old mailbox/history migration and mixed-version refusal.

At this checkpoint, pushed/deployed verification is pending. The following
execution session is authorized to commit, push and deploy for acceptance.
`get_commit.sh`: NOT RUN. Page/SW release, two-browser tests, direct/relay media,
server nginx and post-deploy acceptance: NOT RUN. The prior release evidence
below must not be attributed to this checkpoint.

---

# Historical checkpoints (retain for provenance)

# Active transport-v3 work — 2026-09-14

## Release .8 — 2026-09-18

The real two-account regression additionally found that completed handshake
controls returned the same null result as crypto failure and therefore remained
in Device Inbox, repeatedly sending SOS responses. Successful controls now have
an explicit consumed outcome. Failed Kyber-final transmission retains its capsule
in Account-encrypted storage and retries the same material. Initial SOS/ECDH
intents are deduplicated in the local outbox while the peer route is unavailable;
control retries do not appear as chat history.

Ratchet ACK advancement now retains the same bounded two previous receive epochs
as the responder. The regression reproduces a late epoch-one ciphertext failing
after the initiator processes the epoch-two ACK, then verifies successful decrypt
with the fix. No wire format or suite downgrade was introduced.

SHA-256 PoW round addition no longer allocates rest arrays. Independent native
SHA-256 vectors cover block/padding boundaries; a local 20,000-hash comparison
improved from ~1060 ms to ~213 ms. Difficulty and digest transcript are unchanged.
Node shutdown now awaits the asynchronous HopProbes.close coroutine.

Validation before deployment: all 209 Node + 11 Origin Python tests and 48 PWA
JS suites pass. Both real Chromium two-account runs (private pairing and public
contact request/accept/confirm) pass against EMS: initial key exchange, messages
in both directions, two ratchet epochs, delayed prior-epoch ciphertext after ACK,
recipient disconnect/reconnect with queued delivery, and retirement of completed
handshake controls. Public-mode run also exercised a real initial Route unavailable
failure followed by automatic successful retry. Crypto and transport were not
stubbed. Browser tests start at calculator setup in clean contexts.


## Two-account transport correction — 2026-09-17

A real two-browser run exposed two PWA/Node protocol mismatches before Account
ratchet processing. Core's send path used NodeManager.startProbe, which still
sent an unsigned legacy START_PROBE on a v3 connection (INVALID_ROUTE_AUTHORITY).
The private-route helper also advertised the recipient's locator instead of its
own registered inbound route (ROUTE_BINDING_REJECTED). The v3 send path now uses
Device route authority, selects only the matching Account-owned inbound route,
and advertises that route. Recipient lookup remains ROUTE_STATUS.

Regression coverage includes wrong Account/wrong inbound capability rejection,
and a real two-context browser runner for private pairing or public contact
request/accept/confirm, initial Account key exchange, bidirectional messages and
two ratchet epochs. No crypto or transport implementation is stubbed in that
runner. Browser polling awaits asynchronous storage reads explicitly.


## Connection/PoW follow-up .7 — 2026-09-17

Release `transport-v3-hotfix-20260917.7` also fixes intermittent `Invalid challenge`
when EMS's clock is slightly ahead of the browser. The client permits up to five
seconds of positive clock skew for the signed 15-second challenge; expired
challenges remain rejected, and the Node retains its original expiry deadline.
A signed-handshake test covers the tolerance boundary, expiry and bad signatures.

The .6 production real-login/re-login passed, but DNSS work exceeded the former
240-second test budget. Dedicated Worker mining no longer yields via browser
setTimeout every 4096 nonces (unnecessary off the main thread and susceptible to
background timer throttling). Main-thread fallback still yields; Worker cancel
still terminates the worker. The real-PoW test allows 600 seconds within the
900-second proof expiry. No resource difficulty or authentication check is bypassed.
SW acceptance now consumes fetched response bodies and monitors unhandled
rejections inside the Service Worker itself, in addition to the page.


## WASM follow-up .6 — 2026-09-17

The .5 production calculator acceptance exposed a nondeterministic login failure:
Kyber's Emscripten `var Module` shared the global scope with Argon2. Its exported
functions could land on the wrong object (`M._malloc is not a function`). Release
`transport-v3-hotfix-20260917.6` scopes the Kyber runtime in a closure, memoizes the
active v51 foundation loader and checks all required Kyber exports before boot.
The calculator regression now also invokes concurrent/repeated foundation loads
and verifies the runtime objects remain separate. The .5 network/asset and
fixture-contact checks passed, but its full production login check did not.


## PWA hotfix .5 — 2026-09-17

Release `transport-v3-hotfix-20260916.5` keeps Account contacts/history available
without a Node: workspace rendering and contact persistence no longer await
network restoration or resource PoW. PoW runs in a Dedicated Worker, with
termination cancellation; local route handoff no longer waits for probes.
Node controls display the actual v3 WebSocket URL and DNSS readiness.

Repeated login reuses initialized WASM, recreates cleared Account key containers,
and reports boot failures. Workspace listeners are installed once. First SW
installation and panic lock no longer schedule reloads that discard PIN input;
the release notice cannot intercept calculator clicks. Existing immediate SW
response cloning and pending-DNSS PULL gating remain intact.

Validation: 209 Node + 11 Origin Python tests and 45 PWA JS suites pass.
Real Chromium calculator setup/login/local-note/panic/re-login passes without
crypto or login stubs; the real EMS v3 connection completes DNSS and encrypted
STATUS + PULL (`MAILBOX_DRAIN_RESULT`). A separate browser test proves persisted
contacts/local protected notes work with permanently stalled Node auto-connect,
and checks real PoW Worker output/cancellation. This does not establish two-user
message delivery or E6 protection; the larger security milestone remains separate.


## Interim hotfix — 2026-09-16

Follow-up hotfix is prepared as the `transport-v3-hotfix-20260916.4` release.
The v3 mailbox pull is now gated on the connection's DNSS state: a pending
registration is deferred without issuing `PULL`, and a failed registration does
not create a repeating `DNSS_NOT_AUTHENTICATED` warning storm. Once DNSS is
ready, post-auth work triggers a fresh inbox/contact sync. The logged-in
workspace keeps the network card and account settings expose node controls, so
the calculator gate no longer strands an authenticated account without a way
to connect its EMS node. A browser regression covers the gate, the network
controls and existing contact rendering.

Hotfix commit `c4cf22a1239aa3551bbdbcdbcc32db91e2661028` is deployed to EMS.
The Service Worker now clones successful network responses synchronously before
returning the original response, fixing the production `Response body is
already used` race in both cache paths. Release id
`transport-v3-hotfix-20260916.4` forces old interim workers and caches to
update.

NodeManager marks the v3 socket authenticated immediately after the encrypted
session is established. DNSS resource PoW, route restoration and mailbox pull
continue independently and cannot hold or tear down a healthy STATUS channel.
Clean production acceptance verified the catalog endpoint, nginx WebSocket
Upgrade path, v3 handshake, encrypted STATUS and a Saved Messages LOCAL write.
The production UI acceptance also passed chat rename, password setup, unlock
and protected send.

This hotfix deliberately does not include the E6 local protected-chat threat
model refactor. Argon2id descriptor versioning, topology separation after
device+master compromise, opaque secret handles in a Dedicated Worker/WASM and
the offline-guessing boundary remain a separate milestone. No full
live-runtime-compromise claim is made.

## Interim PWA release — 2026-09-16

Adds the default, renameable Account-local Saved Messages conversation. Text
and recorded-message payloads use the encrypted Account vault with LOCAL state;
no Probe, route lookup, Node submission or receipt is generated. File attachment
to Saved Messages is not implemented in this interim release.

Optional per-chat passwords protect local history only. The wrapping key mixes
PBKDF2-HMAC-SHA256 (600,000 iterations, fresh 256-bit salt) output with a
domain-separated output under the non-extractable Account vault AES key, then
uses HKDF-SHA256. It wraps a fresh per-chat Curve25519 private key with AES-GCM.
Passwords and unwrapped private/wrapping keys are not persisted. The local public
key permits sealed history writes while locked; transport E2EE is unchanged.
Password-derived, domain-separated alias entropy is stored only inside the
Account-encrypted descriptor and participates in L2/L3 alias derivation.
Setting/changing a password re-encrypts all existing message content and queued
outbox content, rotates L2/L3 aliases, and deletes old rows in one IndexedDB
transaction. Failure aborts the migration. Read/unread and receipt metadata stay
inside the ordinary Account vault; the additional layer protects content.
Removing a password requires the old password and migrates history back. There
is no password reset/recovery path. Closing/switching chats or Accounts clears
unwrapped keys and history caches. This is local storage protection, not a claim
of post-quantum authentication or a completed ratchet milestone.

New modules: saved_messages.js, chat_cipher.js, chat_password.js. Native Chrome
checks exercise real IndexedDB migrations, wrong password/master/chat rejection,
L2/L3 rotation, locked incoming writes, transaction abort, reopen/unlock, and UI
rename/password/send with a fixture Account. Call/file browser checks use local
ICE and fixture invitation delivery, not live TURN acceptance.

EMS deployment preparation also preserves node_identity.key sidecars (including
BaseNCRH) during rsync and checks the new PWA assets. The release requires nginx
to forward /dmash-client/v3 to the EMS Node, alongside the existing v1 path.
The interim implementation was first deployed as `b6a4745`; the published
hotfix is `c4cf22a`. `dmash-node` is active and rollback artifacts remain on
the EMS host.
Rollback artifacts are retained by the deploy wrapper under the remote PWA
and Node backup directories. This was an intermediate deploy; no live
authenticated Mesh/ TURN acceptance was claimed.


## Ratchet ACK retry correction — 2026-09-15

Repeated updates now receive an ACK encrypted with both the root and epoch
of `update.from_epoch`. Previously duplicate handling selected the old root
but labeled the packet with the receiver’s advanced epoch, making a lost ACK
unrecoverable. A real NaCl packet test repeats an update after persisted state
reload and verifies both ACKs decrypt while the sender remains at its original
epoch. This closes that retry defect; full ratchet loss/reorder acceptance and
post-quantum protocol validation remain unfinished. No deployment.


## Account file transfer controller — 2026-09-14

The PWA file picker is now a dedicated encrypted DataChannel transfer. It
selects a peer Node only when authenticated STATUS reports S-TURN and
`can_relay_blob`, creates a short-lived signaling session, and sends an
Account-encrypted `FILE_SESSION_REQUEST` inside a Device envelope of the same
type. The request has only an ephemeral 64-hex session ID, expiry, signaling
ticket, bounded size/chunk/hash fields and opaque Account-protected manifest
metadata; no file bytes, RouteID, AccountID or DeviceID are exposed to the
Mesh.

The transfer uses an ordered/reliable `dmash-file-v1` DataChannel. The PWA
generates a random AES-GCM key and nonce per transfer, encrypts 32 KiB chunks
and an authenticated completion marker, waits for encrypted in-order ACKs,
checks the whole-file SHA-256, and exposes progress/cancel/save controls.
Files are limited to 64 MiB in the PWA. Incoming requests do not join or
create a DataChannel until the user presses Accept. Account boot/logout and
all session failures cancel and clear the transfer. Legacy DataURL/media and
chat fallback are rejected.

Focused tests cover the cryptographic channel, ordering, bounds, cancellation,
consent and invitation-only delivery. The native Chrome acceptance helper
transfers an 8 MiB fixture over local direct ICE and verifies size/hash on the
recipient. Live coturn/blob relay, authenticated Mesh delivery and production
installer wiring remain pending; no deployment has been performed.

## Account ratchet foundation — 2026-09-14

Added the isolated `account_ratchet.js` primitive and executable test, then
split packet/control orchestration into the separately loaded
`account_ratchet_runtime.js` module so `core_engine.js` remains a thin adapter. It
derives independent message keys from a 32-byte root, direction, bounded epoch
and random 16-byte message ID with HKDF-SHA-256, derives an epoch root from
fresh entropy, and classifies stale/current/acceptable/excessive epoch jumps.
The modules carry no route, Node, Device or Account identity and are loaded by
the PWA acceptance loader, release manifest and service worker. The runtime
owns the wire packet and update/ACK orchestration:
`RatchetState` repeats one pending update until an authenticated ACK, advances
the sender only after that ACK, handles recipient duplicate delivery
idempotently and rejects conflicting/unbounded updates. Core now carries
explicit classical or `HYBRID_MLKEM768_V1` suites in Account-encrypted
`ratchet_update`/`ratchet_ack` controls. When the peer's ML-KEM-768 public key
is present, a fresh classical seed and Kyber encapsulation are combined into
the next root; decapsulation failure rejects that update without downgrade.
After ACK, epoch packets use root/direction/epoch/message ID; epoch zero keeps
the legacy packet for compatibility. Full multi-peer wire/reorder acceptance
and old-root retirement remain the next ratchet work.

## Active-account audio call orchestration — 2026-09-14

The PWA call button now uses `DmashCallRuntime`: it selects an S-TURN endpoint
from encrypted STATUS on an authenticated v3 connection, creates a signaling
session, and sends an Account-encrypted invitation inside a Device-encrypted
CALL_REQUEST. The call target is captured before asynchronous work; expired
invitations do not enter the durable resend queue. Core rejects SDP/ICE/hangup
in `sendMessage` and ignores legacy incoming mesh signaling. The old Core
offer/answer handlers and sendVoipSignal MSG fallback were removed.

Incoming calls consume the recipient ticket before displaying the acceptance
dialog. Microphone permission and offer processing wait for acceptance.
Cancellation, expiry, disconnect and late CREATE/media results close resources.
Account transitions use existing endCall cleanup. The signaling descriptor is
returned by STATUS without credentials or Account identity.

Tests cover controller cancellation, no MSG signaling fallback, Device-hidden
CALL_REQUEST type, encrypted STATUS service discovery, and existing suites.
`DMASH_CALL_UI=1 ... tools/test_call_browser.py` exercises the real controller
and WebSocket with two native Chrome peer connections and synthetic audio;
the shell and invitation delivery are fixtures and TURN is disabled in that
local test. This is not full multi-node product acceptance.

Remaining call work: live coturn allocation/relay health and installer wiring,
full Mesh/browser acceptance, custom ringtone/display configuration and video
negotiation. The current outgoing request uses ringtone=null (receiver default),
generic caller display name, and audio-only media capabilities. The receiving
dialog uses the locally stored contact name. Pre-Account-login call contents
remain Account-encrypted; only the Device event type can be observed then.
No deployment has been performed.

## Signaling follow-up — 2026-09-11

Added `/signal/v1`, with ticket-scoped join, bidirectional event-driven relay,
bounded queues, expiry and disconnect cleanup. Server tests exercise two
WebSocket sessions, queued offers, answer/ICE relay and replay rejection.
Session principals are random handles. Unknown principals cannot read, write or
delete calls. Health defaults to false; credentials now match coturn's standard
HMAC-SHA1/Base64 REST format. See TRANSPORT_V3.md for the wire contract.

Calls remain incomplete: runtime initialization, admitted session creation,
the concrete PWA ticket/WebSocket adapter, call button orchestration and browser
audio acceptance still need implementation. Prior statements that only deployment
remained were too broad. No deployment has been performed.

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

## S-TURN capability and signaling milestone — 2026-09-12

`NodeCapabilities.can_s_turn` is now canonical. `DMASH_CAN_S_TURN` is the
preferred environment setting; `DMASH_CAN_BE_TURN` remains a compatibility
alias and is normalized into the same value. A descriptor reports S-TURN only
when an injected service health check is healthy, and includes signaling WSS
and TURN URLs without Account, Device or DNSS fields.

`backend/s_turn.py` provides the runtime primitive for short-lived TURN REST
credentials and opaque caller/callee signaling tickets. Credentials use a
RAM-only shared secret and expiry. `STurnService.from_env()` requires explicit
WSS/TURN/shared-secret configuration and performs bounded TURN-listener
reachability before advertising the capability. Signaling sessions accept
one-use tickets, relay only bounded offer/answer/ICE/hangup payloads, expire
independently and delete state on close. Permanent TURN passwords and Account
identity are not stored. coturn installation, systemd/firewall wiring and the
production WSS endpoint remain infrastructure work; they are not deployed.

`backend/session_protocol.py` now validates the encrypted Device payload shapes
for `CALL_REQUEST_V2` and `FILE_SESSION_REQUEST`. Calls have bounded display
name, allowlisted/decoded ringtone (256 KiB maximum), media capabilities and
one-time signaling ticket. File sessions have opaque encrypted metadata,
50 GiB size ceiling, bounded chunks, SHA-256 integrity and resumable flag.
These validators never expose Account/Device identity to the Mesh; actual
WebRTC/coturn transport integration remains pending.

The PWA release and service worker now load `call_signaling.js` and
`call_session.js`. `DmashCallSignaling.WebSocketSignaling` performs anonymous
CREATE/PoW, consumes one-use tickets, validates the signaling endpoint, bounds
incoming/outgoing queues and surfaces ephemeral ICE credentials.
`DmashCallSession` owns browser media tracks and RTCPeerConnection, translates
offer/answer/ICE/hangup to that signaling contract, queues early ICE candidates
and closes resources on failure or cancellation. Core can attach it through
`Core.attachCallSignaling`; `sendVoipSignal` then bypasses ordinary chat MSG.
The legacy Core call button has not yet been migrated to create a session and
send CALL_REQUEST_V2, so product-level call acceptance remains partial.

Verification for this milestone: 209 backend tests, 11 Origin tests and 35 PWA
JavaScript suites pass. A separate local Chrome acceptance helper connects two
isolated contexts over direct ICE with synthetic audio and verifies audio stats
and track cleanup. TURN-relay acceptance remains pending a live coturn service.

This checkpoint addresses authenticated route reconstruction, alias recovery,
and the server/client ephemeral signaling boundary.
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

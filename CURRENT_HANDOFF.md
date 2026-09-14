# Active transport-v3 work — 2026-09-14

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

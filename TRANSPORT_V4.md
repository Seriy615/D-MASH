# Unified Node transport v4 — N0 contract and audit

Status: DESIGN / PARTIAL, 2026-09-25. Audited base: `aa0ad8a` on
`origin/transport-v3`. This document does not describe a deployed protocol.
`TRANSPORT_V3.md` remains the historical implementation contract. The development
plan controls milestone scope; no current v3 client is silently upgraded.

## Decisions for implementation

- Allocate wire version 4 and `/mesh/v4` for every implementation, including
  Python, browser and future native Nodes. Only NODE is a network role. Bind
  version, role, suite, identities, ephemeral keys and nonces into the signed
  transcript and v4 KDF domains. Reject v3 and unknown mandatory profiles before
  resource allocation; no role or version fallback. Retain v3 only as an explicit
  migration transport until the full N8 cutover; it cannot claim v4 privacy.
- Node keys are independent of Account keys and persist behind the local storage
  root. Account logout does not stop transit; full local lock closes sockets,
  cancels work and discards unlocked Node keys. No AccountID enters transport
  identities, KDF, labels, directory entries or mailbox aliases.
- Persist a separately random 128-bit directional DNSS for each authenticated
  Node pair and direction. Reconnect keeps that relationship but creates fresh
  ephemeral keys, transcript and session binding. Registration loss requires
  fresh authorization/PoW; cached success from an old session is invalid. Bind
  proofs to version, both Node identities, direction, DNSS, transcript and expiry.
  Reverse authorization is independent; identity changes require explicit grant
  migration, never an automatic queue takeover. No BootID.
- Membership grants no route/mailbox ownership. Separate peer admission, route
  advertisement authority and store capability. Password admission applies to
  every Node implementation before restricted resources are usable. NODE is not
  a password bypass. Preserve signatures, ownership and production PoW cost.
- Local delivery bindings are process-local. Network advertisements of local
  reachability and forwarded reachability must share a common grammar and
  authority model; do not export a terminal grant or an origin/endpoint flag.
  **Unresolved:** replacement for origin tags, distance metrics, root
  advertisements and publicly verifiable route authority that meets this rule.
  Do not ship the old Probe schema as a privacy-compliant v4 advertisement.
- One bounded next-hop queue handles locally submitted opaque payloads and
  transit. First-arrival aggregation remains 500 ms, with peer/route/global
  quotas, expiry, loop/duplicate guards and backpressure. No padding, cover
  traffic or global periodic Probe refresh is introduced.
- Store-and-forward serves any authorized next hop, including transit. Use
  domain-separated keyed aliases bound to authenticated Node ownership and a
  directional store grant; NodeID or raw DNSS alone cannot retrieve a queue.
  Lease ALL currently authorized entries within quota, await send, delete only
  leased rows; failure releases the lease. Crash between send and delete can
  duplicate; client crash after send can lose unpersisted mail. Account control
  retries and encrypted receipts cover that gap, not a hidden mandatory ACK.
- RecipientEnvelopeV2 remains a proposed terminal envelope, with per-route
  recipient capabilities. Do not collapse routes onto a globally linkable Node
  box key. Transit has neither recipient nor Account keys. End-to-end key
  confirmation/DELIVERED/READ stay inside the opaque payload. Hop acceptance
  reports only adjacent receipt/storage.

## Observability audit of v3 (source evidence)

| Frame/surface | What the adjacent peer sees | Endpoint/runtime implication and v4 action |
|---|---|---|
| HELLO/CHALLENGE/AUTH | DEVICE or NODE, stable signing identity, version, suite, ephemeral keys, nonce/expiry | Explicit class discriminator; use single NODE grammar and version-bound mutual authentication. |
| WSS upgrade | URL, Origin, User-Agent, TLS/network features, peer IP | Distinct client path today. Shared `/mesh/v4` removes artificial path class, but browser-controlled headers/fingerprints remain. |
| Password admission | Fresh challenge, KDF descriptor, transcript-bound proof | Current Device admission cannot gate all Nodes; enforce resource policy independently of role. Credential is password-equivalent, not PAKE. |
| REGISTER_DNSS / NODE_REGISTER | Different operations and authority; Node DNSS freshly generated per socket | Distinguishes runtime class and lacks durable general Node relationship. Replace with common directional registration and independent grants. |
| REGISTER_ROUTE / START_PROBE | Route locator and route authority presented by a Device | Reveals endpoint-facing semantics. Local ownership must remain local; advertisement authority redesign is open. |
| HOP_PROBE_V3 | Stable origin_tag, id/request_id, NCRH, label, metric, hop_limit, lifetime, trace | `trace.length == metric + 1`, metric starts at zero and increments. Exposes exact advertisement distance; origin_tag hashes a locator and is correlatable. N0 blocker. |
| HOP_ROOT_NCRH_V1 | Root NCRH, zero initial metric, growing trace, request IDs | Explicit root advertisement and distance distinguish origin. NCRH knowledge must never grant DATA authority. Replacement design open. |
| HOP_NCRH_STATUS / HOP_ALIAS_BIND | KNOWN/UNKNOWN, NCRH, label, metric/lifetime | Peer-scoped grants are useful; exact metric and correlation with root/probe leak position. Bind only after independent authority, fresh session and expiry checks. |
| ROUTE_STATUS | Device queries global locator; status includes hop reachability | Endpoint-facing lookup must be replaced by Node-local Account API and a common peer control plane. |
| HOP_DATA / MESH_BATCH | Hop label plus unchanged packet id and recipient ciphertext | Labels change but colluding hops can match id/bytes. Session encryption does not hide plaintext frames from the Nodes themselves. No onion-security claim; reviewed per-hop construction remains open. |
| PULL / MAILBOX_DRAIN_RESULT | Device-only queue operation, delivery IDs, ciphertext | Terminal-class inference. Generalize store/drain to all authorized next-hop queues; no selected foreign queue. |
| Errors / STATUS / capabilities | Role-specific operation list and can_accept_devices; resource availability | Use truthful common capabilities/errors, not fictitious listeners or TURN services. Do not include Account/terminal delivery state. |
| Reconnect / sleep | Peer identity, IP, timing, connection disappearance, re-registration | Durable relationship is linkable. Browser sleep remains observable. Revoke unavailable paths and rebuild without claiming always-on relay. |
| Calls/files | Signaling tickets, WebRTC ICE/direct peer addresses or TURN endpoints | Separate media-plane boundary; force-relay limits direct disclosure but relay still sees network peers. |

Evidence owners: `secure_session.py/js`, `node_session.py`, `gateway_v3.py`,
`device_registration.py`, `hop_probes.py`, `hop_routes.py`, `capabilities.py` and
`device_client_v3.js`. This is a source audit, not captured production traces.

## Threat boundaries / N0 gate

A malicious neighbor sees its authenticated peer, local grants, labels, queue
and timing/size. Colluding Nodes can correlate unchanged IDs/ciphertext across
hops. Disk compromise of a Node exposes any unprotected persistent secrets;
live runtime compromise exposes decrypted local transport state. Neither the
Worker nor TLS protects against the runtime itself. Account plaintext/keys must
remain outside transit, but local root/Account compromise is a separate threat.

N0 is OPEN: current role/path, Probe root/metric/trace and endpoint-only resources
violate the requested protocol boundary. Strict browser indistinguishability is
not established by WSS because browser-controlled handshake/network signals
remain. Native adapters require their own trust analysis. Timing/volume/global
correlation is outside the guarantee without additional design, and the plan
forbids silently adding padding/cover. A green interop test cannot close this gate.

## Immediate corrections and regression contracts

The historical HTTP router must return a field-free 410 before touching runtime
state for login/logout/connect/debug/state/peers/messages/rename/read/send. It
has no production enable flag or forwarded-header exception. Peer administration
uses the existing host CLI; any future HTTP admin plane needs separate authenticated
admission. Do not infer public nginx reachability from source mounting alone.

The tracked `node_identity.key.basencrh` is persistent secret input to NCRH
root/extension, not a harmless fixture. Remove it from distribution and ignore
runtime sidecars. Never print its bytes or rewrite Git history. Existing deployed
copies need an inventory and controlled backup/rotation/re-advertisement plan;
removing a repository file neither rotates those copies nor erases Git history.

I1 local Inbox drain contract: one bad ciphertext, policy lookup or Account handler
must not prevent later valid records from being tried. Keep failed records and
return a non-success outcome, never a seen tombstone. Lock/root change aborts
before processing another record. If no stored record can be authenticated, fail
closed (wrong root and total corruption are indistinguishable). Existing Account
filtering and persist-before-dispatch remain. Persistent quarantine/backoff and
Account-side crash idempotency remain follow-up work; one pass tries each row once.

## Migration and next implementation gates

1. Inventory/backup identities, Account vault/history and old mailbox ciphertext;
   add independent encrypted Node keys without reusing Account signing keys.
2. Close Probe/authority privacy design with source and peer-trace comparisons
   before freezing the v4 advertisement schema. Do not simply delete metrics
   while keeping exact shortest-path assertions.
3. Build shared Python/JS v4 handshake/authorization fixtures; reject old versions,
   wrong roles, password bypass, replay and foreign grants. Add browser PoW Worker
   admission limits. Keep v3 storage readers until migration is verified.
4. Integrate NodeRuntime with at least two WSS neighbors and no Account dependency;
   prove N1 -> browser B -> N2 with no bypass and real encrypted payloads. Sleep,
   lock, disconnect, alternatives and unavailable must be observable/tested.
5. Migrate old mailbox ownership only with authenticated old and new ownership;
   retain old ciphertext until verified recovery. A rollback must still read
   existing Account/history storage. No deployment until migration and N8 checks.

H1-H4/R1-R2 still require executable failing regressions before Account integration.
Production SHA, SW state, two-browser acceptance, real TURN and deployment are
NOT RUN for this checkpoint. v4 is not implemented or advertised by this change.

## Account control correction, 2026-09-25 (independent of transport v4)

Ratchet control suites are now `CLASSICAL_ROOT_V2` and `HYBRID_MLKEM768_V2`.
This versions collision/ACK semantics; it does not change the underlying
primitive's version-1 update representation or claim new PCS/PQ properties.
Version-1 control suites are refused explicitly; both peers must update before
starting a new ratchet update. Existing stored roots/history are preserved, and
pending material can be retried under v2 after both runtimes update. No automatic
fallback to v1 collision handling is permitted.

For simultaneous proposals from the same epoch, the lexicographically smaller
random 128-bit update ID wins. The winner records the discarded remote proposal
ID (bounded to two entries) and keeps its own pending material. The loser
atomically discards its proposal when persisting the winner's derived root and
ACK intent. A repeated discarded proposal is consumed without an ACK or root
change. Equal IDs with conflicting proposals are rejected. This is deterministic
state convergence, not fresh X25519 compromise recovery.

Per-Account/peer serialization protects propose/apply/ACK persistence; queued
operations reject a changed Account session. On receive, new root, receive history,
last update and `ratchetPendingAck` persist before ACK transmission. Send false
or exception leaves the incoming Inbox record and ACK intent retryable. Only
successful send clears the matching ACK intent. Lost ACKs are recreated on an
identical update under the original epoch/root. Autonomous retry scheduling,
full vault transaction/session pinning and crash-interleaving acceptance remain
required; these changes do not mark all N4 reliability complete.

Emergency recovery now requires an explicit peer ID, and uses independent
bounded five-second retry slots per Account key generation and peer. Chat
selection cannot redirect recovery. `tools/diagnose_initial_handshake.cjs`
executes real NaCl/Kyber fault scenarios H1-H3 with simulated storage/network;
all three currently FAIL and are tracked rather than claimed fixed.

## N1 crypto profile implementation (opt-in, not deployed endpoint)

`Handshake(..., version=4)` in Python and `Initiator(signing, 'NODE', 4)` in
JavaScript select version 4 explicitly. HELLO, CHALLENGE, AUTH and SECURE records
carry version 4; all signature/transcript/KDF domains use `D-MASH|DMP-C|4|`.
Unknown versions, DEVICE roles in v4, and mismatched peer versions are rejected.
The existing suite, ephemeral X25519, directional keys, replay sequence and
bounds remain unchanged. Python SecureSocket accepts the same explicit version.
Existing callers default to v3; there is no automatic negotiation or downgrade.

Real bundled TweetNaCl/WebCrypto <-> PyNaCl interop verifies both encrypted
directions. Python/Python v4, replay, version tampering and mixed-version refusal
are covered. The old `authorize_node` explicitly refuses a v4 session so v3
permissions cannot accidentally become the unified Node resource contract.
No `/mesh/v4` endpoint, universal admission/grants, browser transit or v4 privacy
acceptance is implied by this crypto foundation. Those remain the next N1/N2 work.

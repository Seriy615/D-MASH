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
  quotas, expiry, loop/duplicate guards and backpressure. No padding or global periodic Probe refresh is introduced. Route-carried
  cover DATA is permitted by the subsequent explicit user instruction, with
  bounded injection through existing grants (see TRANSPORT_V4_DISCOVERY.md).
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
| Password admission | Fresh challenge, KDF descriptor, transcript-bound proof | The current v3 gateway has no Node-password gate; the earlier DEVICE-only proposal is insufficient for unified Nodes. Enforce resource policy independently of role. Stored Kpwd is password-equivalent, not PAKE. |
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


## Directional registration foundation, 2026-09-25

Secure sessions now expose local/peer public IDs from their authenticated
handshake. The v4 resource string is exactly:
`D-MASH|NODE-DNSS|V4|issuer_hex|recipient_hex|dnss_hex|transcript_sha256_hex`.
All hex is lowercase, Node IDs/hash are 32 bytes, DNSS is 16 bytes; self pairs
are refused. The existing SHA-256 activation proof binds recipient as node,
issuer as applicant, DNSS kind, that resource and expiry. Both runtimes enforce
production difficulty 20–24, at most 180 seconds validity, integer wire fields
and exact proof schema; optional elapsed_ms is not part of the wire proof.
Acceptance of a proof alone does not grant routes, mailbox ownership or admission.

Python RelationshipStore persists random independent outbound and verified inbound
DNSS behind keyed aliases and authenticated encryption. A store binding detects
wrong storage keys/Node identity, rather than silently allocating fresh aliases.
Atomic SQLite transactions protect concurrent startup/writes. Existing peer DNSS
cannot change without explicit recovery; corrupt records are preserved/rejected.
A bounded relationship quota fails without evicting existing mailbox relationships.
No socket authorization is persisted. Browser equivalent storage, password policy,
actual channel integration, revocation/migration and resource acceptance ACKs remain
unfinished. These foundations are not enabled on the live v3 network.

Browser Node identity can now load its independent PoW seed from DeviceRoot
material storage, verifies PoW on every load and rejects a changed root session.
Real browser Worker/persistence verification passed with native Python BLAKE3
cross-check, cancellation, bounded worker admission and corrupt-storage refusal.
The runtime still must own cancellation/socket/key cleanup at full device lock.

## Required ordering: Probe before QR/contribution

A transit Node must accept valid bounded advertisements without local Account
contact knowledge. A Node later scanning QR derives its local pair locators and
may query a previously learned route; receiving an advertisement never marks
that Node as terminal or authorizes Account delivery. Contributions stay local.

Executable v3 routing-order regression confirms: advertisement before contact
lookup, no forward authority before alias binding, later lookup succeeds while
leased, expiry fails closed, stale alias binding cannot revive the route, fresh
advertisement plus binding restores it. This is a routing test, not QR UI evidence.

An outstanding liveness gap is now explicit: current START_PROBE advertises the
local inbound route; it does not solicit a missing target advertisement. Learning
a contact after all remote advertisement state expires cannot by itself guarantee
remote-route recovery. V4 needs bounded event-driven discovery/re-advertisement
on late contact binding, send and path loss, with common transit/local grammar,
fresh authority/session binding, request budgets/deduplication/expiry and honest
unavailable on failure. Do not add global periodic refresh, resurrect expired
capabilities, send contributions to transit, or count a fresh advertisement
manually injected by a test as proof the actual runtime recovery exists.

Browser relationship persistence is implemented separately from Python storage:
IndexedDB revision CAS transactions, AES-GCM with keyed-alias AAD, bounded records
and a fixed encrypted store identity binding. The DeviceRoot KDF context is
`dmash/node-storage`, version 4, `directional-relationships`. Root/key/session
changes cannot silently recreate an existing relationship. Concurrent tabs converge
on one outbound DNSS. Runtime lifecycle integration must call close() on full lock;
per-operation session guards and transaction aborts are present, but this library
alone does not own the device lifecycle. Actual two-tab browser acceptance passed.

## Password admission cryptographic foundation

The current deployed v3 gateway has no implemented Node password gate; the plan's
older DEVICE-only policy must not be treated as existing protection. V4 foundations
now implement exact `ARGON2ID_64M_T3_P1_V1` (64 MiB, three passes, parallelism one,
16-byte random salt, 32-byte Kpwd), and HMAC-SHA-256 over a v4 domain plus issuer,
applicant, authenticated session transcript, profile, salt, credential epoch,
fresh nonce and 90-second expiry. Browser derivation requires a bounded cancellable
Worker; native Python/browser Argon2 and transcript bytes match in real tests.
HMAC proofs also pass real JS/Python interop with genuine Node identity work.

PasswordGate checks NODE-only v4 sessions and both identity PoWs, consumes each
challenge once, rejects socket/transcript replay, limits tracked sessions, and
keeps bounded exponential failure cooldown across replacement sockets. Per-session
forget and global revocation APIs exist. This does not yet provide a network endpoint:
listener-level rate limits, configuration/installer credential storage/rotation,
mutual directional gate integration and resource-operation enforcement remain open.
Kpwd is password-equivalent; captured proof/salt permits offline password guessing.
No PAKE claim, raw-password wire field or role-based browser exemption is introduced.

## Composed Node channel (implemented, not production mounted)

After the signed v4 NODE handshake, both directions use the same encrypted
sequence: `NODE_POLICY` → `NODE_ADMISSION` → `NODE_ADMITTED` → `NODE_REGISTER`
→ `NODE_AUTHORIZED`. Policy contains version 4, difficulty 20–24 and either a
password challenge or null. Admission carries the exact password proof or null;
an OPEN side refuses unsolicited proofs. A caller can require a peer password
policy, refusing an OPEN downgrade. Admission succeeds on both sides before
relationship creation/resource work. Registration is the exact directional
DNSS/proof format above; authorization acknowledges the received DNSS and version.
No compatibility fallback or implicit route/store authority is granted.

Resource mining and peer registration validation run concurrently. Disconnect,
invalid registration or cancellation terminates mining. Overall authorization
has a 300-second deadline; each resource proof has at most 180 seconds validity
and is checked again after local mining. Persist the verified peer direction
before its acknowledgment; a reconnect still requires fresh transcript-bound
work. Password revocation is checked before persistence and each channel operation,
including after an awaited receive. Browser HMAC verification also checks that
revocation/forget did not occur while WebCrypto was running.

The browser socket pins the expected authenticated Node ID, requires WSS except
loopback tests, limits handshake frames to 4096 bytes, encrypted frames to 2 MiB,
and queued receive/send bytes to 4 MiB (receive count 64). Handshake timeout is
15 seconds. Closing clears session keys and rejects pending reads. These are
per-socket limits; listener-wide quotas and runtime lifecycle ownership remain open.

Real Chrome/Python WebSocket acceptance covers both directional password gates,
production identity/resource PoW, persisted DNSS reconnect, opaque ciphertext
exchange and revocation. This is an Account-free channel test on loopback, not
deployed WSS/transit, route ownership, mailbox or N1–N8 acceptance. Discovery's
candidate design and unresolved issues are in TRANSPORT_V4_DISCOVERY.md.


## Dedicated browser Worker lifecycle (implemented, not activated)

NodeRuntimeHostV4 owns one dedicated Worker per unlocked DeviceRoot session.
It transfers only independently stored Node seed/Base NCRH and a derived Node
storage key, using exact-sized buffers and clearing source material. The Worker
owns sockets, routing, admission work, relationship storage and optional cover.
DeviceRoot lock/replacement immediately rejects host operations, requests stop,
and enforces termination within 250 ms. Root lock clears Root and Device identity
secret arrays; this is lifecycle enforcement, not a physical RAM erasure claim.

Actual Chrome/Python transit passes with encrypted DeviceRoot persistence,
root-lock cancellation, Node identity reuse after unlock and responsive UI.
Unit tests cover bounded RPCs, buffer isolation and single-session ownership.
Cross-tab leadership, Account logout integration, Account route APIs, native WSS
endpoint mounting and complete N5 lifecycle audit remain open. Release .12 caches
these modules without enabling v4 in the application.


## Native incoming connection owner

NodeListenerV4 applies aggregate limits before v4 handshake/registration work:
eight live connections, two concurrent pending admissions and sixteen attempts per
rolling minute by default. The peer ID is reserved after authenticated handshake,
before password/resource admission; a duplicate cannot trigger another registration
miner or release the original reservation. Session completion/shutdown releases
ownership and closes the channel. Storage and credential ownership remain with
the process host. Endpoint adapters must still enforce pre-upgrade, frame/queue
and TLS policy; this module alone does not mount a production listener.

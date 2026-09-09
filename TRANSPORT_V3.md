# Transport v3 engineering record

## S-TURN capability foundation — 2026-09-09

`can_s_turn` is the canonical Node capability. `DMASH_CAN_S_TURN` is preferred;
the legacy `DMASH_CAN_BE_TURN` setting is normalized to the same field, so
there are no two independent truths. Service descriptors expose
`signaling_wss` and `turn_urls` only after a successful health check. They
contain no AccountID, DeviceID or DNSS.

The runtime S-TURN primitive issues short-lived TURN REST-style credentials
from a fresh RAM shared secret and creates one-use caller/callee signaling
tickets. It relays only bounded opaque offer/answer/ICE/hangup payloads and
prunes sessions at expiry. Secrets, tickets and session state are volatile;
coturn installation and the production signaling WebSocket remain deployment
work and are deliberately not claimed here.

Device-level call/file payload validation is separated in
`backend/session_protocol.py`. `CALL_REQUEST_V2` carries only an ephemeral
call ID, expiry, signaling ticket, bounded display/ringtone data and media
capabilities. `FILE_SESSION_REQUEST` carries an ephemeral session, opaque
encrypted metadata, size/chunk/hash limits and a resumable flag. Both schemas
are intended to be encrypted inside Device Envelope; their validators reject
AccountID, DeviceID, DNSS and unbounded ringtone/metadata input. WebRTC
DataChannel and production coturn integration are still follow-up work. The PWA
release now loads `call_session.js`; `DmashCallSession` owns
`RTCPeerConnection` and media tracks, translates WebRTC events to ephemeral
S-TURN signaling, queues early ICE and closes resources on hangup/failure.
`Core.attachCallSignaling` switches `sendVoipSignal` away from ordinary chat
MSG. A runtime adapter must still supply the authenticated one-time ticket; no
production coturn/WSS endpoint is claimed or deployed.

## Authenticated recovery acceptance — 2026-09-09

Recovery now has a response-driven alias exchange in the production NodeChannel
path. The four-node acceptance test rebuilds a lost middle Node, checks the same
NCRH chain and fresh labels, and delivers opaque HOP_DATA through the rebuilt
path. A separate authenticated test holds one peer's send in flight while another
peer becomes ready, then verifies that a timed-out response cannot install a label.
NodeChannel rejects legacy locator-bearing Node packets. Final `tools/test_all.py`
run passed: 184 backend tests, 11 Origin tests and 33 PWA suites (exit 0).
No deployment performed.

## Hop-label data plane foundation — 2026-09-09

`HopRoutes` now provides a volatile label table scoped by authenticated role
and ingress owner. Labels are independent 256-bit random values. Lookup uses
HMAC with a fresh instance key; rows contain SecretBox-encrypted next peer,
outgoing label or local mailbox alias, metric, expiry and NCRH-in/out. Tables
have bounded capacity/lifetime, explicit revocation and discard keys/rows on
close. No stable Node key or raw RouteID is used in the table's index or
persisted.

`HOP_DATA_V3` is accepted inside authenticated Node MESH_DATA/MESH_BATCH. Its
strict wire fields are packet id, hop_route_label and opaque Device ciphertext;
raw route/account metadata and NCRH fields are rejected. An ingress label is
valid only for the authenticated sending peer. Admission checks the binding;
the existing first-arrival aggregator rechecks it at flush, rewrites the label
and groups by resolved next peer. Local termination reuses mailbox authority
checks. Revoked/expired queued bindings stay unresolved within the existing
RAM queue budget. No stale peer fallback or implicit broadcast is introduced.

The data-plane fixture installs bindings explicitly; Probe establishment is
covered separately by the initiator-advertisement implementation below.

NCRH is a trajectory property, independent of RouteID, Account ID and node
identity. Different people can use the same trajectory, while different
trajectories of equal length remain distinguishable. It is an optimization and
path-selection hint; it never grants authority, identifies a recipient or
replaces reachability and hop labels.

Current Probe implementation now follows the initiator-advertisement model:
the initiator advertises a bounded origin tag; receiving Nodes install
alternative paths back toward that origin and propagate advertisements to
their other peers. Probe does not search for a person or a final Account.
The wire carries no RouteID, DNSS, NodeID or Account identity and every
`HOP_PROBE_V3` carries a mandatory 32-byte NCRH value. Each Node persists a
random 32-byte `BaseNCRH_Node` beside its signing secret. The origin computes
`HMAC-SHA256(BaseNCRH_Node, "D-MASH|NCRH|V3|ROOT\\0" || BaseNCRH_Node)`;
each receiving Node computes
`HMAC-SHA256(BaseNCRH_CurrentNode, "D-MASH|NCRH|V3|HOP\\0" || NCRH_in)`.
Forks copy the same incoming value to each outgoing branch; branch Nodes then
extend it independently. Restart preserves the namespace. Duplicate
next-peer candidates are deduplicated by their path/NCRH key, while distinct
NCRH candidates coexist.

Route selection uses reachability, hop metric, expiry and local labels; NCRH
does not authorize, forward, identify a recipient, or decide ownership. Up to
three path alternatives are retained, including equal-length alternatives
distinguished by their path commitment, while each Device/Node hop label
remains independent.

Every authenticated Node connection starts the same synchronization round,
regardless of whether a backup was restored. Old per-channel pending grants are
cleared synchronously before reading that channel. Each peer has an independent
export worker and connection task. The receiver loop starts without awaiting
recovery socket writes. There is no periodic global topology synchronization.

The exchange for a usable candidate is:

1. A advertises prefix X to B, with a fresh random RAM-only request ID. The
   production Probe has `hop_route_label: null`; no label is issued yet.
2. B computes KNOWN/UNKNOWN from its logical knowledge **before** processing
   that advertisement, records short-lived correlation, and sends the status.
   UNKNOWN remains UNKNOWN for this request even when installation then succeeds.
   A zero hop limit stops propagation, not the status or local reconstruction.
   Metric/loop terminal cases also send status. Capacity failures cannot suppress
   the response. A failed control send closes only that authenticated connection.
3. A accepts a status only for its pending `(peer, request_id, X)`. If its
   original candidate remains authorized and usable, A issues a fresh random
   label owned by B and sends ALIAS_BIND for X. KNOWN and UNKNOWN both acknowledge
   receipt; neither is forwarding authority. A Root-only candidate cannot issue
   a DATA capability or invent a mailbox destination.
4. B accepts a bind only for the exact recently received `(A, request_id, X)`
   and candidate generation. B's candidate uses `ncrh_in = X`, while its local
   `ncrh = HMAC(Base_B, HOP_DOMAIN || X)` differs from X. The received label is
   B's outgoing capability **toward A**. A label forwarding back to its own
   ingress owner is rejected. Duplicate, expired, wrong-peer, wrong-NCRH and
   superseded-request binds do not replace live candidates.
5. Once B has the outgoing capability, it advertises its extended prefix to
   eligible peers. C and D at a fork receive the same prefix and independently
   receive fresh B-owned capabilities after responding. New Device label cache
   entries include the outgoing capability generation so refreshes cannot reuse
   a cached binding to the old remote label.

Exact strict schemas (each also contains the shown `type`):

| Type | Other fields |
| --- | --- |
| `HOP_ROOT_NCRH_V1` | `id, request_id, ncrh, metric, hop_limit, lifetime, trace` |
| `HOP_PROBE_V3` | Root fields plus `origin_tag, hop_route_label` |
| `HOP_NCRH_STATUS_V1` | `request_id, ncrh, state` (`KNOWN` or `UNKNOWN`) |
| `HOP_ALIAS_BIND_V1` | `request_id, ncrh, hop_route_label, metric, lifetime` |

Tokens are lowercase 64-hex strings. Probe's label field is null in current
exports; a received legacy non-null field does not activate forwarding without
the correlated bind. Metric/hop limit are integers 0..15, lifetime 1..1800 seconds,
and trace has metric+1 unique per-advertisement loop tokens. Labels, request IDs,
trace tokens and blinded lookup indexes are volatile. No packet includes RouteID,
route_locator, back_route_id, AccountID, DeviceID, DNSS or recipient identity.

Root advertisements use a fresh request ID and Probe ID but deterministic
RootNCRH derived from persistent BaseNCRH. Roots reconstruct logical edges and
propagate without a fabricated origin or forwarding label. Live authorized
initiator advertisements supply the capabilities needed for DATA. Restoring
Node secrets does not restore a Device's mailbox authority.

The bounded local graph stores encrypted RAM edges keyed by a fresh HMAC of
`(authenticated peer, NCRH_in)`, with NCRH_in/out, metric and expiry. Encrypted,
expiring peer-knowledge rows associate outward peers and KNOWN/UNKNOWN with an
advertised prefix; `graph_snapshot()` joins these relationships. Multiple peers
may recognize one prefix, and one peer may supply multiple prefixes. Within an
origin's candidate set, logical identity is the peer/input-prefix pair, never
the random label. Up to three metric-ranked alternatives are retained.

Semantic requests and received-bind correlation expire after 10 seconds. Socket
writes also have a 10-second limit. A reply after timeout leaves that branch
unresolved; another peer's worker continues independently. Reconnection starts a
fresh round and re-exports all eligible candidates. Unsent exports survive socket
failure within their TTL; a suspended old send cannot consume a newer export.
A failed/cancelled binding send revokes its newly issued local capability.
`sync_snapshot()` reports current-round advertisements, replies, pending requests,
roots, bindings, errors and timeouts per peer. There is no all-network barrier:
each validated bound route is independently usable. Root/Probe/status/bind are
immediate authenticated control traffic, outside the 500 ms DATA aggregation.

## Blind Node backup and recovery — 2026-09-09

The recovery bundle contains only persistent Node secrets: the signing private
identity and `BaseNCRH_Node`, plus version, generation and integrity metadata.
It excludes hop labels, Probe candidates, queues and other transient state. A
random opaque object ID addresses an encrypted bundle in a blind `put/get/delete`
store; the store sees only that ID and ciphertext. The bundle uses PyNaCl
SecretBox (XSalsa20-Poly1305) with a separate random 32-byte recovery key.
Local storage uses restrictive directory/file permissions and atomic writes.
Restore validates and stages both secrets together, rolls back on replacement
failure. The two-file replacement is not a power-loss-atomic filesystem transaction. The restored process receives a new
RAM blind-index salt; it is never recovered from the bundle.

The blind alias salt is CSPRNG-generated on every process startup and is never
derived from signing identity or BaseNCRH. An existing malformed BaseNCRH file
fails startup; replacement is allowed only when the file is absent on first
initialization.


## Node aggregation windows — 2026-09-09

Normal mesh DATA and discovery probes enter a RAM-only aggregation queue.
IDLE has no aggregation timer and no periodic scheduler. The first enqueue
synchronously arms one monotonic deadline at arrival + 500 ms. Later arrivals
join that window without extending it. At the deadline a synchronous callback
atomically swaps the incoming list with an empty list and returns to IDLE.
An arrival at/after an overdue deadline closes the old list before enqueue,
so a delayed event-loop callback cannot accidentally extend the old window.
The next arrival arms its own 500 ms window even if old routing or sends are
still in flight. For arrivals at 0/120/340/499 ms, the first snapshot closes
at 500 ms; an arrival at 510 ms opens the next deadline at 1010 ms.

A separate ordered resolver processes closed snapshots without awaiting socket
sends. DATA resolves the current blind local route at flush time, ignoring
its enqueue-time next-hop hint. A route that becomes local terminates through
the existing mailbox authority check; a missing route remains pending and
never falls back to the old peer or floods. Probes use the current eligible
neighbor set (excluding their incoming peer), preserving discovery semantics.
Groups are keyed by next-hop, not recipient: P1->A/P2->B/P3->A/P4->C produces
A=[P1,P3], B=[P2], C=[P4]. Raw locators remain transient; no new persistent
RouteID storage or Account metadata is introduced.

Each group is split into as many nonempty MESH_BATCH records as needed within
that closed window. Limits remain 128 packets and 512 KiB for the canonical
packet array, including brackets/commas and ASCII JSON escaping. Independent
FIFO peer queues send all those batches; a slow or failed peer blocks only its
own queued sends, never opening/closing future windows or another peer. The
4096-packet / 16 MiB enqueue budget counts incoming, snapshots, unresolved and
in-flight work until completion. No padding, cover traffic or empty batches.
Authentication, DNSS/resource authorization, PoW and keepalive retain their
immediate secure-session paths outside the aggregator.

Send failure/cancellation retains the head batch. Work retries per peer after
1 s (a single attempt is bounded at 10 s); successful broadcast peers are
removed immediately and are not resent. Unresolved routes have an on-demand
retry while work exists. Neither retry mechanism is a global aggregation tick.
FIFO order is maintained within each peer, including across windows and
retries; no global arrival-order guarantee across different peers is implied.
Shutdown cancels timers/workers before DB closure and retains unsent RAM work
for restart of the same engine. Process restart still loses transient queues.
Successful socket writes remain distinct from remote acceptance acknowledgments.

Existing supported durable rows are scanned once at startup into the same
pipeline, with their existing blind target fallback only when no locator is
present. They are deleted only after all intended writes succeed; deletion
failure retries cleanup without resending. Unsupported historical rows remain
untouched. This is not a legacy mailbox migration or crash-exactly-once claim.

Validation: deterministic one-shot-clock tests cover idle, first-arrival arm,
non-extension, atomic/overdue snapshot, independent next windows, slow peers,
actual blind-route regrouping/local delivery/missing routes, count/byte splits
(including the exact byte boundary), FIFO retries, partial broadcast,
cancellation during routing/sending, shutdown/restart, control bypass and
legacy-row retention. The real authenticated two-Node WebSocket test also
sends through TactEngine with the production 500 ms window. Full-suite results
are recorded in CURRENT_HANDOFF.md. No deployment is part of this change.

## Contact bootstrap development — 2026-09-09

The live PWA now advertises CONTACT_BOOTSTRAP_V3 and carries signed ACCEPT /
CONFIRM payloads inside CONN_ACCEPT Device envelopes. Account Ed25519 signs its
public bundle and contribution; the expected public Route key signs the same
body and Account signature. Both proofs bind request id, source/destination
public routes, expiry and phase. CONFIRM also binds the exact ACCEPT digest.
The legacy public bundle format is carried for compatibility with current
Account crypto; this is not a new PQ security claim.

An outgoing request is associated locally with the Account chosen when the
user starts it. Account changes during asynchronous route discovery cannot
silently reassign that request. Incoming requests remain Device-level and
readable before Account login. Acceptance requires the selected Account to be
unlocked. Signed transitions persist before sends; failures leave them pending,
and duplicate/retried ACCEPT can resend the same CONFIRM. A closed Account's
bootstrap waits until that Account opens. Account imports peer keys and pairing
material into its vault, then installs the private Device route capability.

Two real-crypto test suites cover dual signatures, context/expiry/replay,
encrypted ACCEPT/CONFIRM, restart retry, locked Account and idempotent import.
The UI test retains legacy local behavior coverage and adds v3 selected-Account
and failed-send guards. Real multi-node/browser contact acceptance is still
pending; the old Account decrypt control-null ambiguity and transport retry
limitations listed below remain. Current dev release: transport-v3-dev-20260909.2.

## Status and baseline

2026-09-08. Base: `703a5df` on `main`; clean clone, working branch
`transport-v3`. Historical handoffs are evidence of earlier intent, not the
current executable specification. No production acceptance is implied here.

The following inventory was made before implementation:

| Boundary | Executable baseline | Target delta |
|---|---|---|
| Device / Node | JSON WebSocket `/dmp-c/v1`, DMP-C version 2, `CHALLENGE`, `AUTH`, `AUTH_OK`; Ed25519 Device signature of pipe-separated node/session/nonces/expiry | Mutual role-bound authentication, ephemeral X25519, directional encrypted records |
| Node / Node | `ws://host:port`; initiator `{id,challenge}`, responder `{id,signature}`; inbound checks NodeID PoW but not initiator possession | Same v3 record layer, independent directional DNSS authorization |
| Mesh wire | `{t:REAL,d:JSON(packet),x:padding}` or DUMMY; `HOP_PROBE_V3` carries opaque origin tag, hop label, metric, trace and mandatory NCRH; DATA carries opaque envelope | Hop labels, local NCRH, opaque DeviceCiphertext, bounded batches |
| DNSS | PWA encrypted Device material `dnss/v1/NodeID`, 16 bytes; SQLite registry composite blind DNSS / raw RouteID; gateway pending registration cleared after grant | Stable Device/Node DNSS, runtime registration bound to authenticated Device key; rebuild after Node restart |
| Public authority | Route-signed EntryGrantV1 includes NodeID, route key, generation and lifetime; no session/DNSS signature binding | Session-bound proof plus grant plus activation work |
| Private routes | Account-scoped lifecycle and locator configuration; gateway does not distinguish authority | Root-capability proof, no mandatory public grant or AccountID KDF input |
| Control hole | Inbound register/unregister and Probe lack resource authority checks | Fail closed before any side effect |
| Mailbox | SQLite `offline_mailbox(target_hash,packet_json,notification_id)` indexed by locator blind alias; PULL per handle; ACK deletes | Durable DNSS mailbox, all-row leased drain, delete only after awaited successful send |
| Device events | Public contact ciphertext boundary exists, but outer type is visible; private receive tied to active Account | Encrypted Device envelope and Inbox with independent dispatch |
| PoW | Node identity BLAKE3 prefix; resource activation SHA-256 transcript V2, production 20–24 bits, consumed replay cache | Preserve work policy; independently authorize each Node direction |
| Capabilities | Policy flags route/accept/fallback/signal/be_turn/blob; no working S-TURN service | Canonical S-TURN alias and health-based descriptor |
| Tact | 1.5 seconds; per-packet sends, padding, DUMMY; transient queue drops failed sends | First-arrival 500ms window, per-peer bounded batches, no padding/cover, retry retention |
| WebRTC | Core offer/answer/ICE via sendVoipSignal/message transport | Ephemeral signaling WSS plus coturn; Device-encrypted call request |
| Files | Existing message/media path | Encrypted chunks over DataChannel, integrity/cancel/progress/limits |
| Account crypto | S/P/timestamp/shift and bundled Kyber prototype | Loss-tolerant epoch keys with authenticated fresh-entropy updates |
| Installer | Immutable revision pin, systemd/env/nginx/firewall; no CLI password or coturn; selected visibility not used in env output | Idempotent parser, verifier secret file, real password gate and optional coturn |

## Implementation sequence

A. Inventory and repeatable all-suite runner.
B. Shared DMP-C v3 cryptographic record/handshake, Python/JS interoperability,
   then gateway and peer integration with role-separated capabilities.
C. Runtime DNSS ownership and session-bound public/private route authorization.
D. Dedicated durable mailbox database/keys and all-row send/commit drain.
E. Device envelope, encrypted Inbox and account-independent dispatcher.
F. Probe-installed hop labels and local NCRH.
G. First-arrival one-shot 500 ms aggregation windows, peer FIFO retries and duplicate handling.
H. Password challenge/verifier, fragment import and installer.
I. Capability directory, coturn health and ephemeral signaling.
J. Device-encrypted CallRequestV2 and actual call flow.
K. DataChannel encrypted file chunks and UI integration.
L. Account epoch ratchet and loss/reorder/update tests.
M. Full regression, Chrome acceptance, documentation, push and exact-hash deploy.

Each milestone must pass relevant executable tests before commit. Existing
tests are retained; obsolete expectations require an explicit migration note.
`python tools/test_all.py` runs Node, Origin, and all executable PWA suites and
reports every failure. Use Python 3.12 with the pinned client dependencies and
`httpx==0.27.0` for the current Starlette test client.

## Target invariants (PLANNED until supported by integration tests)

### Device boundary foundation (PARTIAL integration)

`device_envelope.js` encrypts the entire canonical DeviceEnvelopeV1 with a
fresh ephemeral X25519 NaCl box. Route, extensible type, packet id, metadata
and opaque Account payload are inside the box. This layer alone does not
authenticate the Account sender; the Account handler must verify its E2EE
payload before marking delivery.

`device_inbox.js` persists envelopes before invoking handlers. AES-GCM storage
and HMAC record aliases use distinct DeviceRoot HKDF domains. Account B stays
pending while A is active; Device handlers can run before Account login.
Unknown local routes are retained encrypted until their policy is restored.
Successful handling leaves a 30-day deduplication tombstone. Callback failure
retains the pending record. Handlers must be idempotent across a crash between
their durable write and the Inbox tombstone. Quotas bound disk consumption.
IndexedDB persistence was also verified in native Google Chrome using the
isolated localhost `tests/device_inbox.browser.html`: encrypted storage,
close/reopen, delivery to B while A stays active, durable deduplication and
pre-login Device event all passed. The test removed its own database. This is
module acceptance, not the required deployed PWA end-to-end acceptance.
Unit tests use an injected transactional store. Web Locks serialize tabs
where supported.

`device_client_v3.js` adds serialized asynchronous handshake processing,
Node identity pinning, request correlation, timeout and disconnect cleanup.
The gateway sends a plaintext `WELCOME` containing NodeID for per-Node Device
identity derivation. WELCOME grants no authority: the same NodeID must verify
the signed challenge. A real JS/Python loopback WebSocket test covers encrypted
concurrent STATUS/PING, role capability limits and wrong identity rejection.
The loader and service worker now include these modules under release
`transport-v3-dev-20260908.1`. NodeManager uses DeviceClientV3 for new
connections, binds stable DNSS, and arms public routes with DeviceAuthorityV3.
The canonical `/dmp-c/v3` and proxy-facing `/dmash-client/v3` are both backend
routes. Known historical `/v1` endpoint paths map to `/v3`; an explicit
descriptor `dmpcEndpoint` can override that mapping. The existing EMS proxy
configuration still needs verification before deployment.

PULL now retrieves the session's whole queue and persists opaque boxes in
encrypted local staging before dispatch. Boxes without an available local key
remain staged. The native Chrome fixture also passes close/reopen of this raw
staging phase. Public contact senders wrap the existing contact ciphertext in
a CONN_REQUEST Device Envelope; public registration stores grants encrypted
and borrows route keys only for the operation, wiping them in finally.
Core v3 polling delegates to this Device pipeline. Private route derivation
and normal Account send/receive are now connected; contact Accept/bootstrap
and explicit control outcomes remain incomplete, so this is not deployable.

### Device Account-route aliases (user clarification, 2026-09-08)

Persistent Device lookup is `HMAC(DeviceAliasKey, RouteID) -> Account slot`.
Account RouteID is transient during Device decrypt, then replaced by a blind
alias in the pending record. The local route index also stores blind handles.
Even opening the encrypted Device records does not reveal a retained raw
Account RouteID. Directional route authority/box key material is separately
encrypted under DeviceRoot; the Device derives transient wire routing values
from that capability when registering/probing/sending. This is distinct from
storing raw RouteID as a lookup identifier. Existing ephemeral route settings
are blinded after Device unlock and reconstructed from Account pairing state.

The Account Vault owns `blind Device route alias -> Account peer` association.
The Account authenticates/decrypts its payload and writes its vault before a
DELIVERED receipt. The Device never decrypts Account ciphertext: it wraps the
opaque payload, chooses the Node and performs transport. Private locators use
direction/generation-separated HKDF Ed25519 capabilities and recipient route
box keys derived from the two contributions; Account IDs are excluded.

The old crypto implementation shares mutable keys, so Account boot waits for
current Inbox processing and route installation before replacing them. New
Inbox work pauses during that transition. Tests cover A active/B stored,
unlock B/write/receipt, bad sender proof, concurrent boot, opaque payload
handoff, and absence of raw Account routes even in decrypted Device records.
The historical decrypt null result is ambiguous for control packets; those
remain pending rather than being marked successfully processed. The epoch
ratchet milestone must provide explicit control success/failure outcomes.

`device_authority_v3.js` reuses encrypted `dnss/v1/NodeID` material, attempts
socket binding without new work, and mines again only for
`DNSS_NOT_REGISTERED`. Concurrent binding attempts share one operation. Route
proofs bind the operation, fresh request id, session transcript, DNSS, Node,
authority key, generation and expiry. Private registration uses PRIVATE_ROUTE
work and does not send a public EntryGrant. AUTH_OK now advertises the Node's
resource work difficulty; the client accepts the production 20–24-bit range.
Tests exercise reconnect, runtime loss, distinct proof ids and wrong-session
signature rejection. Node data reception also checks current route authority
at mailbox insertion so an expired/revoked registration cannot keep receiving
through an old routing-table entry. Route registration first attempts an
idempotent reconnect without work and mines only after INVALID_RESOURCE_POW.

The historical stability test now checks that the page and service worker
have the same current release instead of pinning the old release-55 string.
All historical v50–v55 behavior assertions remain in place.

Validation at this checkpoint: 134 backend tests, 11 Origin tests, all 31 PWA
suites pass using `tools/test_all.py`. No deployment or production acceptance.

Account identity, ratchet, content and receipts stay in the Account layer.
Device plaintext is `{version,route_id,type,packet_id,device_metadata,account_payload}`;
all fields are encrypted to the destination Device. Type is an extensible
bounded string. Route is for local dispatch, not intermediate forwarding.
Locked Account payloads are persisted encrypted at the Device layer before
being processed after unlock. Device fetch/storage is not Account DELIVERED.

Device DNSS survives socket loss and IP changes; socket authentication rebinds
it. Node restart discards registration/routes, but retains mailbox ciphertext
and durable mailbox alias keys. No BootID. Node directions use distinct DNSS
and independent work. PULL never accepts a caller-selected queue.

Mailbox drain selects all quota-bounded rows under a short lease, sends one
logical result, and deletes only its reservation in a transaction after send
success. Failure releases the lease; crash after send may duplicate delivery.
Client packet-id dedupe is required. Routing and mailbox key lifetimes differ.

Public routes use Route signatures; private routes use pairing contributions
and root capability. Both authorize the specific session/DNSS/generation and
required work. NCRH never authorizes ownership. Each hop replaces a random
local label using encrypted local metadata; Account identifiers never enter
locator derivation or Node descriptors.

Batching aggregates routes sharing a next hop in first-arrival 500ms windows, with item/byte and
queue bounds and FIFO within a route. Control frames are immediate. Without
padding and cover traffic this reduces timing granularity but does not prevent
global traffic correlation.

S-TURN means live ephemeral signaling plus TURN relay, with short-lived TURN
credentials. Call request carries expiring session material and a bounded
ringtone inside Device encryption; SDP/ICE uses signaling WSS. File content
uses encrypted/integrity-checked DataChannel chunks. Password proofs bind a
fresh nonce and transcript; no raw password on wire or in browser storage.

Epoch message keys are independently derived from root/direction/epoch/random
message id. Repeated self-contained updates tolerate loss; acknowledged old
roots are erased. Fresh X25519 entropy is required for compromise recovery;
ML-KEM needs exact implementation review before any hybrid/PQ security claim.

TODO: future DHT can carry the same NodeDescriptor serialization; no DHT is
part of this change. No anonymity, formal PCS/PFS, or PQ claim is made from
schema or unit tests alone.

## Baseline verification (before production changes)

Python 3.12.14, Node 24.19.0, pinned requirements: Node 98/98 pass;
Origin 11/11 pass; PWA 23/25 suites pass. Two pre-existing failures:
`historical_webauthn_release.test.js` executes the old release patch against the
new loader with an incomplete DOM fixture; `historical_webauthn_source_regression.test.js`
expects WebAuthn implementation inside `release.js`, now moved to runtime
modules. These failures are retained and must be migrated without weakening
WebAuthn requirements. Baseline test output is local, outside Git.

## B1: shared secure-session implementation

IMPLEMENTED: `secure_session.py` and `secure_session.js`, shared v3
HELLO → signed CHALLENGE → signed AUTH, X25519 ephemeral keys,
HKDF-SHA256, separate send/receive keys, XSalsa20-Poly1305 encrypted records.
Roles DEVICE/NODE, identities, suite, both ephemeral keys, nonces and expiry
are bound into the transcript. The Python async adapter serializes concurrent
sends including sequence allocation; failures destroy the session.

Wire suite: `X25519-HKDF-SHA256-XSALSA20POLY1305`. Canonical JSON uses sorted
ASCII property names, ASCII-escaped strings, safe integers, boolean/null and
arrays/objects, maximum depth 32. Signed hash is SHA256 of
`D-MASH|DMP-C|3|HANDSHAKE\0` plus canonical `[hello,challenge_without_signature]`.
Responder and initiator signatures have distinct domain labels. HKDF salt is
that hash; IKM is `X25519\0 || u32be(32) || shared`; info is the protocol domain
plus suite. First/second 32 bytes are initiator→responder/responder→initiator.
A future hybrid suite must bind its own suite and length-delimited KEM inputs;
this implementation accepts no ML-KEM or silent fallback.

SECURE frames have version 3, integer sequence, standard canonical base64
ciphertext. Secretbox nonce is 16 zero bytes plus u64be(sequence). Directional
keys and fresh connection keys separate nonce domains; sequence is strict,
starts at zero and is bounded to 2^32−1. Maximum plaintext record: 1 MiB.
Malformed, replayed or reflected incoming records close and clear keys.
Python/JavaScript clear mutable key buffers and release references; neither
managed runtime promises forensic erasure of all library/internal copies.

IMPLEMENTED: FastAPI `/dmp-c/v3` DEVICE endpoint with encrypted PING/STATUS;
NODE roles and unimplemented resource operations fail closed.
PARTIAL: v3 is not yet the active PWA or Node↔Node transport. Existing v2 path
remains unchanged pending authority/mailbox migration. This is not completion
of milestone B or the overall refactor.

Validation: 111 Node tests pass (98 baseline + 13 new). New tests include
RFC 5869 vector, real bundled TweetNaCl↔PyNaCl interoperability for both roles,
mutual possession, wrong identity/role/signature/expiry, challenge/auth replay,
record tamper/reflection/replay, fresh reconnect keys, erasure and real ASGI
endpoint tests. PWA baseline still has the two documented historical failures.
Cryptographic references: RFC 5869 (https://www.rfc-editor.org/rfc/rfc5869),
RFC 7748 (https://www.rfc-editor.org/rfc/rfc7748); references do not constitute
an audit of this protocol composition.

## B2: Node↔Node migration

IMPLEMENTED: `network.py` now uses the common v3 handshake and secure socket.
Saved endpoints pin their known NodeID on reconnect; new peers are authenticated
as first-contact identities and must still satisfy the existing Node identity
PoW. Both directions independently generate 128-bit DNSS, mine and verify
resource work bound to recipient NodeID, sender NodeID, DNSS, and the fresh
session transcript. NODE_REGISTER/NODE_AUTHORIZED are encrypted, immediate
control operations. One direction's work never authorizes the reverse.

Node data operations are MESH_PROBE/MESH_DATA; NODE_CONTROL currently supports
keepalive. Device operations including PULL are rejected on Node channels.
Old REAL/DUMMY wrappers exist only at the local adapter boundary and are not
sent as cleartext; padding is not transmitted by the adapter. Tact scheduling
and existing locator-bearing packets still await milestones F/G.

Compatibility: peers must upgrade together; there is no automatic fallback to
the old unauthenticated-initiator handshake. Host:port dialing retains its
existing ws transport; explicit wss URLs retain TLS verification. Encrypted
DMP-C is additional protection, not a substitute for a deployment's TLS/WSS.
Node authorization currently uses a new directional DNSS per connection;
Device DNSS persistence remains a separate unfinished migration.

Validation: 113 Node tests pass, including two real loopback WebSocket peers,
independent directional DNSS/work, data transport, Device-operation rejection,
and refusal when one direction supplies bad work. Identity-prefix mining is
mocked only in these focused integration fixtures; resource proof verification
is real with reduced test-only difficulty. Production difficulty is unchanged.

## Historical test migration

The two baseline WebAuthn failures are now fixed in tests, without changing
production biometrics. The executable historical test follows release.js's
runtime loader and tests runtime_fixes.js, where enrollment/unlock/gesture
logic now lives. It retains RP, ES256, resident/platform credential, PRF,
single-prompt enrollment, encrypted wrap and trusted pointerup assertions.
The source guard now checks the same runtime module and explicit PRF fallback.
The obsolete fixed v44 badge expectation follows the actual release identifier.

Full verification at this checkpoint: Node 113/113; Origin 11/11; PWA 25/25
suites. No deployment or Chrome acceptance has been performed.

## C/D: backend DNSS authority and mailbox integration

IMPLEMENTED in the v3 backend: runtime Device registrations bind DNSS to the
handshake-authenticated Device key. Reconnect with that key preserves DNSS;
restart discards registrations and requires new work. The durable mailbox
alias uses a distinct HMAC domain and includes the authenticated Device key,
so a different key claiming the same raw DNSS after restart cannot retrieve
old mail. No raw DNSS or AccountID is persisted. Runtime registry/route indexes
use a fresh random key, separate from the durable mailbox alias key.

REGISTER_ROUTE/START_PROBE/UNREGISTER_ROUTE require a Route authority signature
binding NodeID, DNSS, session transcript, operation, unique request id, kind,
route id, generation and expiry. Public routes additionally require the
Route-signed EntryGrant with matching Node/generation/expiry. Private locators
commit to a direction-specific root-derived Ed25519 verifying capability;
the Node receives no pairing root and requires no Public EntryGrant. Private
activation uses the distinct PRIVATE_ROUTE work context. Production work
thresholds remain unchanged. Both registrations and replay caches are bounded.

When the v3 runtime is active, historical v2 resource operations are disabled
at the capability boundary; its PING/STATUS remain for upgrade detection.
New route operations cannot bypass the authority gate through the old endpoint.
This is a protocol cutover and requires the matching PWA migration before
production deployment; the current PWA is not yet migrated.

IMPLEMENTED: destination route bindings direct opaque v1 ciphertext into
`mailbox_v3.db` under blind DNSS. Multiple routes converge on one queue.
REGISTER/UNREGISTER route state never deletes that DNSS mailbox. PULL accepts
no queue selector and returns one MAILBOX_DRAIN_RESULT with all current entries,
then deletes exactly its lease after awaited successful send. Failure or
cancellation releases the lease without deletion. Crash leases expire in 30s;
send timeout is 10s. New arrivals during send remain for the next PULL.
Node acceptance reports NODE_ACCEPTED, not Account DELIVERED.

Limits: 128 entries and 512 KiB of base64 ciphertext per DNSS, 64 KiB per
ciphertext, 64 MiB global ciphertext quota, within the 1 MiB logical record
limit. SQLite uses WAL/FULL and mode 0600. Routing tables/local bindings/seen
state are reset on production Node startup; mailbox and peer directory remain.

PARTIAL: legacy locator mailbox rows are retained unchanged, not automatically
converted to DeviceCiphertext. Migration/recovery of those rows must be handled
before promotion. Device packet-id dedupe, Inbox, PWA authority generation,
password gating and notification wake integration remain for later milestones.
Existing node routing metadata still uses its historical encryption helpers;
full runtime-only route storage-key migration belongs to milestone F.

Validation: all 132 Node tests, 11 Origin tests and 25 PWA suites pass. New
coverage includes wrong owner, wrong session/DNSS/operation, replay, missing
work, wrong/expired grant, public/private authority, restart/reconnect, mailbox
quota/id conflict, cancellation/failure/crash, concurrent drain and arrivals,
and a real database/gateway-operation/transport flow with two routes into one
DNSS and one all-entry response. Browser acceptance remains unperformed.

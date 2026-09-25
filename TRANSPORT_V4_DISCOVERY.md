# v4 discovery — implemented transport, partial integration

The primitives and bounded JS/Python routing runtimes are implemented and tested
through the native FastAPI gateway and a real browser Worker. Account/Inbox,
mailbox and provisioning integration remain incomplete; this is not an N0 privacy
proof. The design addresses the outstanding N0 gate before reusing v3 Probe on the
new Node channels. The development plan remains authoritative. The v3 graph's
global origin_tag, public root advertisements, metric and trace cannot simply
be copied into v4. The new authenticated channel by itself does not fix them.

## User steering: route-scoped NCRH, 2026-09-25

The user identified that a device-wide NCRH would correlate independent local
routes now that the phone itself is a Node. Adopt route-specific derivation for
v4 instead of exporting a common device root. Proposed exact construction:
`HMAC-SHA256(BaseNCRH, "D-MASH|NCRH|V4|ROUTE\0" || canonical_route_id_bytes)`.
The separator denotes one zero byte. RouteID is exactly the 32 decoded bytes
of the route identifier, not its hex/base64 text. BaseNCRH is an independent
secret 32-byte random Node material, never NodeID/AccountID/password or a public root.
Keep the result stable across ordinary reconnects; use distinct route IDs for
distinct directional/public/private routes. Account IDs do not enter this KDF.

Only the local route owner needs RouteID for initial derivation. Transit must
not request that global identifier: further hop transformations operate on the
received NCRH with a separate v4 HOP domain. NCRH remains an index, never proof
of route ownership or permission to claim/deliver/drain a mailbox. Do not export
the old device-root advertisement alongside these values: it would undermine
the intended separation. Existing v3 functions stay explicit migration code.

This removes the common deterministic value across different local routes;
it does not make repeated observations of the same route unlinkable, hide the
adjacent Node identity, or by itself prove origin/terminal indistinguishability.
Equal graph values can also mean shared transit, so equality alone is not proof
that an Account terminates on that device. Probe semantics/metrics/authority
still need separate review. The opaque-discovery candidate below must reconcile
whether/where to expose such route-specific NCRH; this steering is not permission
to reintroduce a global cleartext route locator or device-root announcement.

## User steering: random Probe hop TTL

Every newly originated Probe samples its hop TTL with the system CSPRNG, uniformly
from the configured inclusive range (initial default 4–15, hard maximum 15).
Sample once per Probe, independently of its RouteID, NCRH and Account. Copies
of that same Probe keep the sampled budget; retransmission does not replenish it.
Each receiver consumes one hop: an incoming TTL of 1 allows local processing but
no onward forwarding; 2 becomes 1 on the next wire. Reject zero, non-integers and
values above 15 on receipt. No public initial-TTL field, decrement counter,
absolute metric or path trace is added. Time expiry remains an independent bound.

Randomization makes observed TTL ambiguous about distance; a value near the
maximum still constrains possible distance and it is not an anonymity proof.
Untrusted relays can lie about TTL, so rate/fan-out/deduplication/expiry quotas
are still required. A short draw can miss distant routes: event-driven retries
must be bounded and may create a fresh Probe with a fresh draw, never a global
periodic refresh or unlimited expanding search. Default range is a resource
policy, not a claim of guaranteed network reachability.

## Local capabilities and opaque discovery

A local route binding holds its independent route signing/box keys, the local
Inbox destination and its public/private ownership evidence. Accounts register
these bindings through a local API; a neighbor's Node identity never creates one.
Transit holds only adjacent peer/session scoped labels and bounded queues.

Candidate discovery uses an event-driven opaque Probe. The destination's per-route
box public key is known to the initiator from pairing or a public descriptor; it
is not a Probe header. Encrypt a bounded query using the existing audited NaCl
box primitive with fresh ephemeral key/nonce. The encrypted query contains a fresh
random challenge, expiry, protocol domain/version and an independent reply box
public key. Neither global RouteID, AccountID, authority certificate, path list,
origin tag nor numeric distance is exposed to transit. Do not add an observable
recipient hint computed from a public descriptor: that would allow matching a
Probe to a known public route.

Each hop validates the common grammar, resource admission, size/rate/expiry quotas
and duplicate cache, installs a peer-scoped return capability, rewrites that
capability and forwards via the same first-arrival 500 ms aggregation mechanism.
An immutable ciphertext digest may be used only as a short-lived local dedupe key;
it is not a durable route locator. Local delivery capability checks are independent
of peering. Knowledge of an NCRH or received ciphertext never creates ownership.
NCRH-derived graph indexing can remain local and encrypted; no public root or
absolute hop-count advertisement is necessary in this candidate.

Every Node performs bounded trial opening against its local route bindings in a
Worker. A matching local binding does not add a terminal field or stop otherwise
eligible Probe fan-out. The owner returns an opaque, recipient-encrypted response
through the ordinary DATA pipeline and return labels. The response authenticates
the query challenge, expiry and both reply/route contexts using the route authority
key. The initiating Node verifies that proof before publishing a usable route to
its local caller. Reuse existing NaCl primitives with explicit domain separation;
no claim of a new onion construction or post-compromise privacy is implied.

A common DATA frame can carry a hop-local opposite-direction label offer. Each
forwarder substitutes its own offer and installs the corresponding next-hop
mapping, so an opaque reply can establish the forward path without disclosing its
purpose. Local-origin and forwarded frames use the same operation and queue. A
local binding and a transit mapping are different internal destinations of the
same kind of inbound label. No end-to-end receipt is exposed outside the envelope.
Detailed binding/revocation/lease semantics and authenticated byte encodings must
be finalized and tested before treating this proposal as an implemented contract.

## Late QR and path loss

Before QR/contribution is known, the future recipient acts as ordinary transit.
Keep only a bounded, expiring opaque Probe cache; installing a new local binding
may retry local opening of retained queries. Never retain arbitrary traffic forever.
If a query has expired or was lost at restart, adding the contact or attempting a
send initiates fresh, bounded discovery. The new peer can discover the opposite
private direction after deriving both contributions, establishing a return path
at the same time. There is no global periodic refresh. Missing discovery results
remain unavailable; UI must not display a usable path based only on a contact row.

## Route choice and required validation

Exact shortest-hop routing conflicts with publishing no absolute position.
Candidate selection should compare locally observed discovery round-trip time,
local next-hop availability/backpressure and bounded alternative paths, rather
than publish a zero-origin metric and increment it. This optimizes observed path
quality, not a proven minimum hop count. The change must be explicit in acceptance
criteria; do not report an exact shortest-path test as satisfied by a latency test.

Before implementation acceptance, validate at least:

- Genuine N1 -> browser B -> N2 forwarding, no bypass, no active Account at B.
- Owned public/private route proof; forged/unknown/replayed proof cannot publish a
  usable local route or claim another local Inbox. Peer membership alone is insufficient.
- Probe before QR, cache expiry/eviction, restart, opposite-direction late binding
  and event-driven recovery with no injected test-only routing table.
- Common local/forwarded frame traces and label rewriting; no origin/terminal
  marker, public global RouteID, path, root advertisement or exact position.
- Bounded fan-out, route trials, queues, packet sizes, request/peer/global budgets,
  lifetime, duplicate/loop handling, rate limiting and concurrent candidate limits.
- Route/grant revocation on peer disconnect, reconnect session replacement, lost
  labels, expiry and successful alternatives; unavailable when alternatives fail.
- Device full lock cancels work and closes all sockets/keys; Account logout does
  not stop the unlocked Node's transit.

## Unresolved items and limits

This is a design candidate, not completed N0/N2. Offline mailbox delegation needs
an explicit compatible authority story: do not give an intermediary the recipient's
private route key merely to answer discovery. Owner-signed alternative delivery
capabilities and their migration/expiry must be analyzed with store-and-forward.
Public descriptors, private pairing, multiple Accounts and resource quotas need
shared grammar and actual integration, not test-only seeded labels.

Unchanged ciphertext permits correlation by colluding hops even without a public
packet ID. Timing, lengths, topology, selective disruption and repeated active
queries remain relevant. Browser-controlled WSS headers/TLS/IP/sleep fingerprinting
is not eliminated. These residuals prevent an absolute indistinguishability claim;
removing explicit wire markers is only a narrower, testable protocol property.
No padding, cover traffic, global refresh or misleading capabilities are authorized
by this proposal. Protocol/cryptographic review is still needed; green tests alone
cannot prove its privacy claims.

## Active short-TTL probes and separate discovery authority

Random initial TTL only blurs passive distance inference. A malicious admitted
neighbor can send TTL=1: if only the Account's terminal can answer an authenticated
query, the response reveals a locally held terminal capability. Do not claim
endpoint privacy from random TTL alone.

Resolve this in the v4 route contract by separating discovery keys from recipient
payload keys. The route signing authority certifies a discovery signing key,
discovery box key, recipient box public key, generation and bounded validity.
Discovery agents (including explicitly authorized store/forward delegates) may
hold the two discovery secrets and this certificate; they never receive the
route owner's signing secret or recipient payload decryption secret. All agents
answer with the same certificate/challenge proof grammar. A valid answer proves
current discovery authority, not Account termination. Delegation provisioning,
next-hop binding, retention, expiry/renewal and revocation still need runtime
implementation; merely adding certificate code does not close N0.

Implement the certificate as version 4, four fixed 32-byte public values
(route_id/discovery_sign/discovery_box/recipient_box), generation, issued_at and
expires_at as unsigned big-endian u64, signed by route_id. Validity is at most
30 days, issued_at may be at most 60 seconds ahead, generation starts at one.
Signature input begins `D-MASH|DISCOVERY-CERT|V4\0`. RouteID is the Ed25519 route
verification key; no NodeID or AccountID occurs in this certificate. The caller
must obtain/pin the certificate from the existing authenticated contact/route
flow, not accept an arbitrary certificate from the first neighbor.

Opaque queries/replies use existing NaCl box with fresh ephemeral X25519 key and
24-byte nonce: binary ephemeral public key || nonce || box, encoded canonical
base64. Query lifetime is at most 180 seconds. A query contains a random challenge,
independent reply box public key, route_id, version, type and expiry. The encrypted
reply carries the pinned certificate and a discovery-key signature over the query
challenge/reply key/expiry and SHA-256 of the signed certificate transcript. The
initiator verifies both signatures, all bindings and expiry before accepting a
route. The route ID and certificate remain inside these encrypted envelopes.
An outer observed NCRH is not part of the ownership proof and grants no rights.

## User steering: route-carried cover DATA, supersedes earlier no-cover scope

The user now explicitly proposes that any authorized transit Node may originate
DUMMY traffic on a route passing through it. This supersedes the earlier blanket
no-cover requirement for this feature; preserve the first-arrival 500 ms batching
contract. Cover DATA uses an existing valid peer/session label and normal DATA
queue/grants, with a syntactically valid opaque recipient-envelope-sized payload
whose authentication will fail at the recipient. No visible DUMMY type/bit,
distinct length or transport response identifies it to intervening Nodes.
A Node does not acquire foreign route labels or mailbox rights by generating it.

Terminal handling must authenticate/decrypt before durable Account Inbox insertion.
A payload failing every eligible local recipient-envelope key is silently dropped
without Account handler invocation, receipt, ratchet mutation or contact discovery.
Malformed outer frames still follow ordinary resource/protocol rejection policy;
valid opaque data gets the same hop acceptance handling regardless of terminal
success. Unopenable data cannot be positively identified as cover: wrong-key,
corrupt and obsolete-key traffic has the same outcome. Preserve pending key/route
migration windows and distinguish locked/unavailable keys from actual failed
cryptographic authentication; the former is a bounded deferred-delivery condition.

Cover injection is bounded by per-route/peer/global byte and work budgets, respects
backpressure, active grants and route expiry, and cannot starve real queued data.
Do not probe unknown routes, wake/advertise all contacts, or publish an Account-
specific activity flag as a side effect. Because an intermediate store cannot
distinguish cover, it consumes normal offline mailbox quotas; never exempt it with
a visible bypass flag. Define retention/overflow policy before enabling generation.

Adding cover only to windows containing real data does not hide start/stop activity.
If idle cover is enabled, a separate bounded local scheduler creates arrivals;
first-arrival windows still begin at that arrival and end 500 ms later rather than
becoming a permanent global batching timer. Rate, idle behavior, mobile/background
lifecycle and privacy/performance acceptance remain to be implemented. Colluding
hops can still correlate unchanged ciphertext, lengths and timing; cover alone
is not proof of anonymity or endpoint/runtime indistinguishability.

## Implemented routing slice and limits, 2026-09-25

`node_routing_v4.py/js` now compose admitted channels, the discovery certificate
exchange and NCRH/TTL primitives. They operate without any Account API. Callers
supply locally authorized discovery bindings and opaque delivery handlers; the
runtime never receives recipient payload keys itself. This slice is not mounted
in production or connected to the PWA Account lifecycle.

Wire batches are `{type:MESH_BATCH,version:4,packets:[...]}` (1–32 packets,
256 KiB input limit). Probe packets have exactly type/version/box/return_label/
ncrh/ttl/expires_at; DATA packets exactly type/version/label/offer/payload/
expires_at. All labels are random 32-byte hex capabilities scoped to one adjacent
channel. A forwarded Probe gets a new return label and transformed NCRH, with
TTL reduced once. Its label maps to the incoming peer's return capability.
An encrypted signed reply travels as ordinary DATA and its reverse offer is
replaced at each hop, installing the usable forward direction. The origin only
publishes a route handle after verifying its pinned certificate and reply proof.
Handles bind the actual channel object, not just the peer's persistent NodeID.

First-arrival windows use monotonic time and close after 500 ms; expiry uses wall
clock independently. Peer senders operate independently, with a 10-second send
timeout; failure revokes the peer's labels and pending queue. There is no durable
store/retry guarantee in this slice yet. Current bounds: 8 peers, 32 local bindings,
4096 labels and duplicate entries, 128 queued packets per peer, 1 MiB queued bytes
across peers, 32 incoming Probes per peer/minute, 180-second packet lifetime.
Only 64 most recently retained valid Probes are available for late local binding,
subject to expiry and live incoming peer. Eviction/expiry requires fresh discovery;
no indefinite retention or global refresh is introduced. Invalid/unknown/expired
labels never create bindings. Stale DATA is silently discarded without killing
an otherwise usable peer. Every packet still requires current channel admission.

Actual Chrome two-socket transit passes: Python N1 and N2 have only the browser as
a neighbor, no direct bypass; browser has zero owned routes and no Account runtime.
Discovery starts without preinstalled hop labels, recipient binding is installed
only after N2 receives the early Probe, then an opaque payload reaches the holder
of the independent recipient key. Incoming/outgoing labels differ; stopping the
browser makes the route unavailable. Loopback WebSocket evidence is distinct from
remote WSS, worker/UI performance, multi-path/fork/shortest-route selection, public
and private Account migration, listener admission quotas and full N2 acceptance.

Still missing: runtime certificate/delegate provisioning and generation/revocation
storage, descriptor migration, native/PWA host lifecycle, Worker isolation, route
selection/alternative recovery, expired-cache event-driven Account integration,
mailbox persistence, DUMMY generation/filtering and real production v4 cutover.
The earlier design candidate and endpoint-privacy limits remain open; no N0–N8
completion claim is justified by this routing slice.

### Numeric TTL boundary remains an explicit N0 gate

With globally enforced maximum 15 and mandatory decrement, receiving TTL=15
reveals that an honest adjacent peer originated this Probe. Random sampling
4–15 only changes how frequently that exact observation occurs. This is stronger
than a general timing leak and must not be silently accepted as origin hiding.
An async clarification is pending on whether to retain this numeric-counter
behavior or prioritize the strict origin-hiding requirement and revise the TTL
mechanism. Until resolved, current code is a tested routing implementation with
this known protocol distinction, not completed N0 privacy.

## Cover DATA implementation contract

RecipientEnvelopeV2 is inside the existing opaque NaCl box, with exact fields
`type:RECIPIENT_PAYLOAD`, `version:2`, random 32-byte hex `packet_id` and string
`payload` (the opaque serialized Account envelope). A terminal adapter returns
accepted only after box authentication and this inner schema check. No available
recipient keys returns deferred, not discard; authenticated runtime/storage
lifecycle owns deferred persistence. A failed box or invalid inner envelope returns
only a local discard outcome. Neither outcome becomes a wire receipt or flag.

Cover boxes have a genuine fresh ephemeral X25519 public key and nonce, followed
by random bytes in place of authenticated ciphertext, with canonical base64 and
normal envelope size bounds. They have no DUMMY discriminator. Probability of
accidental successful tag authentication is cryptographically negligible, not a
logical certainty; normal payload/Account validation remains required afterward.
Discovery return handlers must likewise silently ignore unopenable/invalid replies
instead of closing an admitted channel when cover arrives on a return capability.

Initial injection policy is at most four packets and 16 KiB of decoded cover bytes
per minute per Node, at most two per peer per minute, using live transit mappings
only. Injection yields to existing queued/sending work and expires with the current
channel/label; no foreign grants, probes or route activation are manufactured.
Idle scheduling and product defaults are separate lifecycle integration work.

Cover injection and an explicit start/stop idle scheduler are now implemented in
both routing runtimes. The default scheduling interval is cryptographically
sampled between 15 and 45 seconds; configurable bounds are 15–300 seconds. It
never creates a route, refreshes a Probe or bypasses a busy queue. Rolling 60-second
packet/byte/peer budgets still apply. Runtime close cancels the scheduler. It is
not enabled by default or connected to production/PWA policy yet. Default cover
size is 1024 decoded bytes; a caller may select 256–16384. This is not a traffic-
distribution matching or anonymity guarantee; size/timing correlation remains.

RecipientPayloadV4 implements the inner V2 envelope codec and returns local
accepted/discard/deferred outcomes. Hosts still must connect accepted records to
the durable local Inbox and persist/retry deferred records as part of N3; this
codec itself does not provide durable storage or Account authentication.
Real Chrome transit acceptance now injects cover from B while N1 discovery is
pending, and again after a route exists. No channel is closed, N2 discards cover,
its accepted-payload count stays unchanged, then a second real payload succeeds.
This test uses the recipient codec at the delivery handler and no Account runtime.

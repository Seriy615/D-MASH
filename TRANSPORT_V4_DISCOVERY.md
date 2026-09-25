# v4 discovery design candidate — not yet implemented or a privacy proof

This proposal addresses the outstanding N0 gate before reusing v3 Probe on the
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

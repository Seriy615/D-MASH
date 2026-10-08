# Proposed STORE_FORWARD_V1 profile — not implemented or negotiated

This document defines the next review boundary, not permission to enable a new
wire profile. Storage remains inactive and its verifier is injected. Existing
runtime/deployed endpoint behavior must remain unchanged until Python/JS vectors,
real-session negative tests, browser transit and migration acceptance pass.

## Existing authenticated sources and incompatibility

`backend/secure_session.py` and browser `secure_session.js` authenticate exact
HELLO/CHALLENGE fields, Node identity and version4 in a signed handshake transcript.
`backend/node_channel_v4.py::_policy` and browser `node_channel_v4.js::policy`
accept exactly four NODE_POLICY fields. Admission, NODE_ADMITTED, directional
NODE_REGISTER and NODE_AUTHORIZED then complete in order. Unknown policy fields
currently fail; there is NO existing extension negotiation. `node_registration_v4`
proves the applicant's outbound DNSS to the storing peer, including fresh secure
transcript. `node_admission_v4::_context` requires NODE/NODE and identity work;
PasswordGate is an additional admission check. None grants route ownership.

## Explicit profile selection and negotiation

Proposed catalog configuration adds independently authenticated local
`required_profile=STORE_FORWARD_V1`; it is not accepted from an untrusted socket.
This is a mandatory v4 application profile, preserving one wire role NODE.
Peers configured for this profile extend NODE_POLICY with exact fields
`profiles` and `required_profiles`, each a sorted unique bounded ASCII array.
Both contain STORE_FORWARD_V1 initially. Reject unknown required entries,
missing required intersection, duplicate/unsorted values and excessive arrays.
Do not try the legacy policy after rejection. An old peer fails explicit upgrade
required; separate existing legacy v4 configuration remains available only when
explicitly selected before connection, with no mailbox capability.

After NODE_AUTHORIZED and before routing starts, exchange encrypted
NODE_PROFILE_CONFIRM with profile and negotiation digest. Canonical digest includes
both policy objects ordered by NodeID and secure transcript hash; each side must
match it. TLS termination cannot remove a field from authenticated encrypted records.
No mailbox/grant messages are processed before confirmation. UI/config must expose
incompatibility, not silently use the existing v3 Device gateway.

## Canonical representation

Use the existing secure_session.canonical serializer in Python and its shared JS
counterpart: sorted object keys, compact ensure_ascii JSON encoded as ASCII (the same bytes in UTF-8), safe nonnegative integers
only for new profile fields. No floats, undefined, NaN, alternate hex/base64 or
extra object keys. Identity/commitment/nonce are lowercase fixed64 hex; DNSS is
lowercase fixed32 hex. Ed25519 signatures use canonical padded base64, exactly
64 decoded bytes, validated against authenticated NodeID.

For object body B and ASCII context C, signed bytes are exactly:
`ASCII("D-MASH|NODE-STORE|V4|STORE_FORWARD_V1|") || ASCII(C) || 0x00 || canonical(B)`.
Hash is SHA256 of these bytes. Signature field is excluded from B. Separate C
values: GRANT, BIND, ROUTE_GRANT, ROUTE_REBIND, MIGRATION. This is a proposed new
domain, never interchangeable with admission/registration signatures.

## Store grant and fresh-session binding

Storing Node S issues a signed GRANT body with exact fields:
`version=1, issuer=S, recipient=R, grant_id, generation, direction,
issued_at, expires_at, policy="store-forward-v4", max_records, max_bytes`.
Bounds: max_records1..128, max_bytes1..524288; safe integer times/generation.
`direction = SHA256(domain(DIRECTION) || canonical([R,S,dnss_R_to_S]))`.
This means R's proven outbound DNSS, stored as S.relationship.inbound; using the
opposite direction is a rejection. Grant generation/expiry/policy are immutable;
renewal means explicit distinct owner/migration. Persist issuance before sending.
Grant hash covers the exact signed body and is the storage owner commitment.
Membership does not authorize grant issuance: local store policy must allow it.

R binds with signed BIND body:
`version=1, issuer=S, recipient=R, grant_hash, direction,
transcript_hash, challenge, expires_at`.
S issues a fresh challenge on the authorized session, at most90 seconds, once only;
S verifies R's Node signature, exact fresh transcript, its own persisted valid
issued grant, direction from this session's registration and local policy/revocation.
Session object identity and grant hash produce an opaque local capability.
No persisted grant or correct Node signature alone waives fresh session admission.
Reconnection repeats this binding with the same owner; restart restores encrypted
issuance/relationship records, never old session capability objects.

## Durable route binding and relabel

Node admission/grant proves mailbox ownership, not arbitrary routing rights.
Each hop that issues a durable label must first possess explicit route authority:
a verified local route certificate/private capability, or an authenticated upstream
hop delegation already recorded for that exact binding. Store grant is insufficient.
The authorized hop issues signed ROUTE_GRANT:
`version=1, issuer, holder, binding_id, binding_generation,
route_authority_commitment, store_grant_hash, expires_at`.
It contains no AccountID, endpoint flag or caller-supplied callback name. The issuer
must persist the binding's authorized continuation independently of socket labels.
A local continuation points to an opaque local ownership slot; transit continuation
points to an authenticated downstream binding. These meanings stay local.

Fresh relabel requires holder-signed ROUTE_REBIND:
`version=1, issuer, holder, route_grant_hash, store_grant_hash,
transcript_hash, challenge, expires_at`.
Issuer verifies both grants, current binding generation/revocation, continuation
availability and its fresh once-only challenge. It then mints a fresh random label
for this session and acknowledges the exact route grant hash. Old labels cannot
be reclaimed by NodeID or an arbitrary string. Changed continuation requires a
new authenticated binding/migration; it never overwrites a pending old binding.
Records remain blocked while downstream binding/local ownership is unavailable.
Discovery reply callbacks remain transient; persist neither closures nor signed
query private state. Binding issuance must be integrated at actual routing authority
creation, not inferred later from a DATA packet's offer string.

## Universal drain and framing

After binding, all Nodes use the same encrypted control envelope and verbs
STORE_GRANT, STORE_BIND, ROUTE_REBIND, STORE_DRAIN. These are universal hop
operations, never endpoint-only PULL. No new role or endpoint marker. A single
STORE_DRAIN captures ALL eligible current rows; a random snapshot ID with ordered
bounded fragments carries this one snapshot. Each fragment includes index/count
and opaque packets. The adapter invokes storage guard immediately before each
fragment and awaits every send. Delete exactly leased rows only after complete
send; failed/partial/cancelled send retains the entire snapshot. There is no
mandatory recipient ACK. Crash send/delete duplicate and receiver pre-persist loss
windows remain documented. Fragment bounds must align with existing256KiB batch
limit and64KiB per storage record; define shared vectors before implementation.

Equal verbs do not establish endpoint privacy by themselves. Negative wire tests
must compare transit and local flows, resource policy, batching/timing and error
behavior. No anonymity claim follows from this proposal.

## API fixture boundary and ownership proposal

Next pure profile fixtures should define canonical bodies/bytes/hashes/signatures,
negative extra-fields/wrong direction/transcript/generation/expiry vectors and
Python↔JS equivalence. Exact candidate interfaces:

- `verifyStoreBind(channel, issuedGrant, challenge, proof)` returns opaque owner
  capability bound to exact channel object, immutable grant hash and expiry.
- `verifyRouteRebind(channel, ownerCapability, issuedRouteGrant, challenge, proof)`
  returns opaque current route binding; storage receives immutable commitment,
  generation and expiry, not an arbitrary wire label.
- `guardSnapshot(ownerCapability, bindings)` checks admission/session/revocation,
  each current route binding and record expiry synchronously before each fragment.
- `verifyMigration(oldProof,newProof,tuple)` checks both complete owner proofs and
  immutable migration ID/source/destination before storage journal mutation.

Proposed new shared fixture JSON and pure codecs: node_store_profile_v4.py/js plus
own tests. Integration later touches node_channel_v4.py/js (negotiation),
node_relationships_v4.py/js (verified directional source only if needed),
node_routing_v4.py/js (persisted authority, labels, drain), node_service_v4.py
(protected key/store lifecycle), Node Worker/Host storage bridge, catalog/bootstrap
required-profile plumbing. Account agent owns route_discovery_v4; do not alter it.
No new endpoint, profile activation or production schema migration in this slice.

Remaining design implementation gate: a ROUTE_GRANT issuer must demonstrably derive
its authority from existing local binding or transit delegation in real routing
code, and both sides must store grant material under Node root. A signature over
an arbitrary caller-provided authority commitment is NOT that derivation. Fixtures
alone cannot close this gap; code-path review and adversarial real-channel tests
are required before activating any mailbox operation.

## Review correction: hop-local authority and actual creation paths

The phrase `route_authority_commitment` above MUST NOT mean a public certificate
hash, routeID, encrypted discovery blob hash, or another end-to-end constant.
Existing v4 has PROBE and DATA only, NOT a GRANT packet. New ROUTE_GRANT is proposed
and must not be described as already authenticated by the current implementation.

For issuing hop S, derive a stable private key:
`K_hop = HMAC-SHA256(NodeStorageKey, ASCII("D-MASH|NODE-STORE|V4|HOP-COMMITMENT") || 0x00)`.
For each local authority edge allocate fresh random32-byte edge_salt, kept encrypted
only at S. Define:
`commit = HMAC-SHA256(K_hop, domain("HOP-AUTHORITY") || canonical([S,H,direction,edge_salt_hex,edge_generation]))`.
H is the immediate holder, direction is the exact local relationship commitment.
The local encrypted edge record binds commit to its validated continuation.
No peer chooses edge_salt, local continuation, callback or authority evidence by
posting a string commitment. Each hop uses its own key and fresh edge_salt; even
the same public certificate produces unrelated commitments on different edges.
Stable commitment permits only intended continuity with the same immediate holder.
Public routeID/certificate stays in existing recipient-encrypted discovery; it is
never copied into grant/bind fields. NCRH and discovery packet hashes are likewise
not substitutes for this authority. A local trusted resolver may retain certificate
association encrypted at rest, not expose it to intermediate Nodes.

Actual Python creation paths and required changes (JS has matching methods):

1. `bind_local` verifies certificate and discovery signing/box keys. This is a real
   local authority source, but a callback is not durable ownership. N3 local owner
   registry must resolve a verified opaque owner slot and generation before an
   authority edge can be persisted. `_answer_binding` calls `answer_query`; only
   a verified decrypt/answer result and that registered slot can back its offered
   durable edge. Reply ciphertext and certificate stay outside clear grant metadata.
2. `_receive(PROBE)` validates authenticated incoming peer, bounded expiry/TTL,
   rate and dedupe, then `_label(neighbor,(peer,return_label),expires)` allocates a
   reverse return edge. This proves only a holder-scoped PROBE return capability;
   it does not prove an Account route owner. Persist such an edge as PROVISIONAL
   bounded current-session reachability state, not durable edge authority. Its
   continuation requires a separately verified adjacent return-edge grant; an
   unverified peer string cannot survive a session change.
3. `_receive(DATA)` first matches `(peer,label)` to an issued edge and bounds packet
   expiry. This capability possession authorizes traversal of exactly that edge,
   not arbitrary registration. For transit, its new `_label(targetPeer,(peer,offer))`
   reverse edge must be backed by a verified adjacent grant for that incoming offer
   plus the already authorized forward edge. Neither successful DATA receipt nor
   payload inspection tells a transit Node whether recipient discovery verified.
   Therefore durable authorization must be hop-capability delegation, not an
   inferred end-to-end confirmation. Every immediate grant issuer certifies ONLY
   its own local edge and continuation; upstream grants never expose downstream
   grant hashes/commitments or certificate IDs in their public bodies.
4. `discover` has a `verify_reply` callback and returns a route pinned to its exact
   channel. Its verification authorizes local recipient route selection, but cannot
   be broadcast as a global route hash. The selected adjacent edge must independently
   have the authenticated hop grant. `send`'s callback offer needs an explicitly
   registered local Node inbox/control slot before it can become durable.
5. `_remove_peer` currently deletes edges. New persisted edge records must be
   suspended, not reassigned. After restart, revalidate local owner generation or
   downstream grant/relationship, then holder's fresh rebind. Missing/deleted owner,
   changed downstream grant, retired generation or expired authority blocks drain.
   Never reconstruct a continuation from a caller-supplied target or old label.

Required delegation ordering is still an integration gate: issue/persist local
edge grant before advertising its label; exchange/verify adjacent grant before
accepting durable DATA into that edge; publish activation only after both sides
have matching edge commitments. PROVISIONAL traffic may use bounded
transient current-session routing during this exchange; NO payload on an
unpromoted edge is accepted into durable storage. Transit cannot classify its
encrypted contents as discovery versus user data and must not pretend to do so. Failure keeps the edge provisional
or suspended and reports not-ready; it does not invoke v3. A real routing fixture
must exercise these paths before codecs can be considered integration-ready.

## Exact bounds and mutable challenge ledger

For this profile `domain(C)` is the ASCII prefix
`D-MASH|NODE-STORE|V4|STORE_FORWARD_V1|` (38 bytes), followed by ASCII C and one NUL;
contexts have the fixed spellings specified here, no user-selected contexts.
Canonical integers are0..9007199254740991; issuance/expiry use integer UTC seconds.
PROFILE_CONFIRM includes exact local/remote canonical policy digest and secure
transcript32 bytes. Challenges are random32 bytes, expire within90 seconds,
maximum32 pending per channel and256 globally. Ledger key is exact channel object,
verb and nonce. A correctly formed response consumes its challenge atomically
BEFORE signature/grant mutation success is published; rejection consumes it too.
A repeated proof, different verb/channel or expired challenge fails without mutating
owner/edge records. Channel close invalidates all its challenges. Issuance persistence
and activated binding publication use journaled ordering; no admission flag is
set merely because signature validation started. Limits and local policy apply to
all Nodes equally; none is keyed to endpoint status.

Grant/body/signature encoded operation must be <=4096 ASCII bytes. Max record is
65536 ciphertext bytes and mailbox512KiB/128 rows as admitted. Encoding uses canonical
base64 (not hex) at wire boundary. Each fragment is exactly one record and must
be <=96KiB serialized operation, below existing256KiB secure batch limit. One
snapshot has1..128 fragments; snapshot_id is random32 bytes and index is0..count-1.
No fragment combines unrelated snapshots. The ALL callback guard runs before every
fragment; total awaited snapshot timeout remains10 seconds with30-second lease.
Slow links may retain/retry the entire snapshot; do not partially delete to evade
the stated ALL lease contract. Explicit timeout tuning requires paired lease/test
changes. Operation validation must reject oversize before base64 allocation.

This defines bounds, not endpoint indistinguishability proof: record sizes and
control timing remain observable and need comparative transit/local acceptance.

### Authority scope clarification

A hop grant certifies scoped reachability/capability ownership at its issuing Node,
NOT end-to-end Account or recipient authenticity. Transit never verifies encrypted
recipient discovery and never receives Account keys. Its authority is the exact
locally issued edge in the authenticated neighbor namespace, with bounded quota,
expiry and immutable continuation. Promotion proves possession and continuity of
that issued edge (including its adjacent continuation), not ownership of a global
route. Only the originating local discovery verifier authenticates the recipient.

Adversarial acceptance must replay another peer's valid label and another edge's
valid grant, cross-bind label/grant/continuation mappings, replay old-session proof,
and substitute downstream generation after reconnect. Each fails without changing
the original edge or ciphertext. A legitimate same-neighbor fresh-session rebind
restores only the same persisted continuation; route changes require explicit new
edge and migration. No global route proof is required or disclosed by transit.

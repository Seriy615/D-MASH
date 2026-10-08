# Account routes over local Node v4 — proposed migration contract

Status: **PROPOSED / NOT IMPLEMENTED**, 8 October 2026. Complements
[NODE_V4_ACCOUNT_CUTOVER.md](NODE_V4_ACCOUNT_CUTOVER.md). Scope is N3 and compatible
C/D/E, contact portions of N4. This does not activate runtime transport, complete
N0–N8/A–M/E6, or implement authenticated ratchet recovery. The current default
Account path still uses the explicitly temporary v3 gateway.

## Current gaps and module ownership

`AccountNodeTransportV4.configurePeer(peerId, certificate, localRouteId)` verifies
only the route certificate's own signature, then separately writes the inbound
and outbound maps. It does not authenticate the relationship of that certificate
to `peerId`, bind an Account signature, protect against generation rollback, or
atomically publish both mappings. A self-consistent attacker certificate is not
a certificate authenticated by the intended Account.

Account agent owns pairing parser/validator, authenticated peer mapping, Account
migration journal and guarded adapter integration. Node agent owns root-session
host, encrypted local bindings, local owner APIs, activation/retirement and neutral
request dispatch. UI agent owns explicit upgrade, route readiness, Account selection
and retry/error/cancel controls. Core activation follows integrated review; no module
may silently convert a v4 failure into a DeviceClientV3 call.

## Private pairing V2: serialized bundle

Use a new `DMASH_PAIRING_V2` payload, `version:2`, `transport_version:4`. Reject
unknown fields, malformed canonical encodings and oversized input before crypto.
UTF-8 serialized bundle ceiling: 12 KiB; nesting and exact schema are fixed.
No networking occurs merely because a parser accepted a bundle.

Exact fields, in canonical JSON order:

| Field | Encoding / meaning |
|---|---|
| type, version, transport_version | Exact constants above |
| pairing_id | 32 random bytes, lowercase hex; stable across retry of this offer |
| generation | Safe integer >=1; monotonically increases for this Account/peer relationship |
| issued_at, expires_at | UTC seconds; lifetime <=24 h, future skew <=60 s |
| previous_binding | Null for first pairing; otherwise 32-byte committed binding digest |
| intended_peer | Null for a fresh out-of-band offer, otherwise exact peer signing public key |
| contribution | Fresh 32 random public bytes, hex; transcript uniqueness, never a route secret |
| account_keys | `{signing, box, kem_profile, kem_public}` described below |
| inbound_certificate | Exact existing DiscoveryCertificateV4 |
| signature | 64-byte Ed25519 signature, lowercase hex |

`account_keys.signing` and `.box` are 32-byte lowercase hex public keys. Initially
`kem_profile` is explicitly `LEGACY_KYBER768_BUNDLE_V1`, `.kem_public` is the existing
1184-byte public bundle in canonical unpadded base64url. This compatibility label
makes no ML-KEM/PQ/PCS certification claim; N5 must verify provenance and define a
separate negotiated cryptographic update. A future profile requires a new recognized
profile and vectors, never silent reinterpretation of these bytes.

Signing bytes are `UTF8("D-MASH|ACCOUNT-PAIRING|V2<NUL>") || U32BE(body_length) || body`,
where `body` is canonical UTF-8 JSON of all fields except `signature`, with exactly
the field order above and `account_keys` order shown. Integers serialize in decimal
without exponent; only ASCII key material/profile strings occur. Certificate order
is `version,route_id,discovery_sign,discovery_box,recipient_box,generation,issued_at,
expires_at,signature`; its signature is included in the Account-signed body. Parsers
must reserialize and compare bytes before verification. Use one shared serializer
and JS/Python vectors, not arbitrary JSON object order at call sites. `<NUL>` denotes one zero byte, not printable placeholder characters.

Verification order: size/schema/canonical bytes → recognized versions/profile →
validity → Ed25519 Account signature → existing certificate signature/validity →
pinned expected Account identity/intended peer → previous binding/generation rules.
The certificate must remain valid through the bundle expiry, and its generation
must equal the offered pairing generation. All key roles must be distinct; reject
reuse of Account signing key as route authority/discovery/recipient key. Never use
an Account key as the Node identity.

For a new contact, an imported self-signed Account key is only an out-of-band/TOFU
identity candidate. Signature validity proves key possession, not the human's identity.
Display the fingerprint/verification boundary and pin it on explicit import/accept.
For an existing contact, compare against the already authenticated Account identity;
a mismatch is a replacement request requiring a separate explicit flow, not recovery.

## Route key ownership and bilateral binding

Each participant independently generates an inbound route's secret seed under its
unlocked local root. Domain-separated derivations produce independent route-sign,
discovery-sign, discovery-box and recipient-box keys. Public pairing contributions
never derive those secrets. Only public certificates enter pairing bundles. Neither
peer receives the other's inbound route signing/recipient secrets. The local Node
may unwrap the recipient envelope but its payload remains Account-authenticated E2EE.
Transit has neither recipient private keys nor Account E2EE keys.

An offer's `intended_peer:null` can be shown before the other Account is known.
Each offer is single-use after a bilateral binding commits; copying/retrying identical
bytes for that same exchange remains idempotent. A different peer requires a newly
issued offer, not reuse of a committed null-target offer. Importing it yields a pending
candidate, not an active transport map. The response
bundle sets `intended_peer` to the offer's Account and records the offer digest in
an authenticated local exchange record. The offer owner signs a binding acceptance
that references *both* full bundle digests, both Account identities, both contributions,
both inbound certificate digests, transport/profile and expiry. The peer countersigns
the same binding digest. This two-signature receipt is the authority for activation.
Both receipts are opaque payloads over normal Node routes, never transport fields.

`binding_digest = SHA256(domain || canonical ordered binding body)`, with domain
`D-MASH|ACCOUNT-ROUTE-BINDING|V2<NUL>`. Order participants by Account signing key;
direction is explicit by mapping each identity to its own inbound certificate. Each
signature signs the digest with distinct receipt phase domains so a pairing bundle
signature cannot be replayed as an activation receipt. Equal identities, duplicate
contributions, self-pairing and contradictory bundle digests are rejected.

Receipt retry reuses the exact signed bytes and stable exchange ID; a later duplicate
cannot create another relationship. This route agreement is **not** the N4 E2EE key
confirmation. UI separately exposes CONTACT_SAVED, ROUTE_PENDING, ROUTE_READY,
KEY_PENDING and ESTABLISHED. ESTABLISHED still requires authenticated Account key
confirmation under the future N4 transcript/recovery contract.

Generation rules: lower generation rejects; equal generation accepts only byte-identical
binding digest (idempotent retry); a greater generation must cite the current committed
binding digest and carry both existing authenticated Account signatures. A new bundle
alone cannot replace a current mapping. Crossed first offers remain pending until a
single two-signed binding is selected; deterministic minimum tuple of ordered bundle
digests is the proposed winner, but both parties must confirm that winner. Late receipts
for a losing candidate cannot replace an active map. N4 collision handling remains separate.

## N3.2 canonical binding and receipt bytes (frozen implementation boundary)

The inactive `account_route_binding_v2.js` module accepts two serialized canonical
Pairing V2 bundles and an explicit trusted local snapshot: two already selected
Account signing identities, plus `committed:null` for first pairing or
`{generation,binding_digest,participants}` for the last committed binding. The
snapshot is local authority supplied by the later Account journal, never data read
from a received offer. First pairing requires generation 1 and null predecessor;
updates require equal generation/predecessor in both offers. Equal-generation retry
must have the identical committed binding digest. Neither new signed offers nor a
pure helper can determine whether the caller supplied the latest persisted snapshot.

Exact canonical binding object order:
`type,version,transport_version,kem_profile,generation,previous_binding,participants,expires_at`.
Constants are `DMASH_ACCOUNT_ROUTE_BINDING_V2`, 2, 4 and
`LEGACY_KYBER768_BUNDLE_V1`. `participants` contains exactly two records ordered by
lowercase Account signing public key. Each record has exact field order
`account,bundle_digest,contribution,certificate_digest`. Bundle digest is SHA256 of
the complete canonical UTF-8 Pairing V2 serialization, including Account signature.
Certificate digest is SHA256 of that bundle's canonical certificate JSON including
signature, using the already specified certificate field order. No unknown fields,
noncanonical JSON, alternate encodings or received replacement certificate are accepted.
Binding expiry is the smaller bundle expiry. Binding serialization ceiling is 4096
UTF-8 bytes. The pure API reconstructs binding bytes from both verified bundles;
it never accepts an arbitrary caller-supplied binding object as verified. Binding digest is SHA256 of
`UTF8("D-MASH|ACCOUNT-ROUTE-BINDING|V2<NUL>") || canonical_binding_bytes`.
The full bundle digests cover all Account public keys, intended peers, pairing IDs,
route certificates and validity, even where the binding body projects fewer fields.

Receipt exact field order is `type,version,phase,binding_digest,signer,signature`:
`type=DMASH_ACCOUNT_ROUTE_RECEIPT_V2`, `version=2`, phase `ACCEPT` or `CONFIRM`.
All digests/public keys are 32-byte lowercase hex; signature is 64-byte lowercase hex.
Receipt signing body is the canonical object without `signature`. Signature input is
`UTF8("D-MASH|ACCOUNT-ROUTE-RECEIPT|V2|" + phase + "<NUL>") || U32BE(body_length) || body`.
The domain and body both bind the phase; the digest binds the complete binding.
Receipt serialization ceiling is 2048 UTF-8 bytes. Parsing reserializes and compares
exact bytes before cryptographic verification. Shared Ed25519 encoding/R/S guards
from Discovery V4 apply before the existing NaCl signature verifier.

**Deterministic receipt roles refine the provisional offer-owner wording above:**
the lexically smaller Account is always ACCEPT signer and the larger always CONFIRM
signer, regardless of which UI initiated the exchange. Creating CONFIRM requires a
validated ACCEPT for this exact binding. Verification requires both distinct valid
receipts; input list order does not matter. Retrying signing uses deterministic
Ed25519 over unchanged bytes. Signatures are never transferred between phases,
Accounts, bundle pairs, certificates, predecessors or binding generations.

Both targeted bundles must name the opposite trusted Account; null-target first
OOB offers remain candidates; generation >1 requires both offers targeted. Equal Accounts, duplicate pairing IDs/contributions,
or reuse of any signing/box/route/discovery/recipient public-key bytes across the
two participants, or identical KEM public bytes, reject. A null-target offer's one-time consumption across different
peers is a journal responsibility; this pure module cannot implement global replay
storage. Every receipt operation rechecks expiry. `verifyReceipts` must receive the
current committed snapshot again and returns `BILATERAL_CANDIDATE` or
`IDEMPOTENT_REPLAY`, never Node/map activation, human identity verification or N4
ESTABLISHED. It does not mutate storage or any key array.

Crossed offers are ranked only within identical ordered participants, generation and
predecessor. Compare the tuple `(participant[0].bundle_digest,
participant[1].bundle_digest)` lexically. The comparator returns an ordering, not an
active mapping; both participants must sign the same winning binding. No minimum
computed from locally observed offers proves global agreement. A later conflict with
an already committed equal generation rejects, even if its tuple ranks lower. The
later journal must atomically pin the selected digest and guard concurrent signing/
commit; the pure codec cannot prevent two signatures authorized by concurrent callers.

## Limited bootstrap route: avoid activation circularity

Pairing receipts cannot depend on the not-yet-ACTIVE Account mapping. Introduce a
separate `BOOTSTRAP_ONLY` local owner state, permitted after explicit QR import or
validated public request/reply capability, before the bilateral binding is committed.
It may advertise the offered certificate through the ordinary Node routing mechanism,
but its local handler accepts only bounded versioned pairing-control ciphertext for
that exact pairing ID and expected offer digest. It cannot deliver user messages,
release an Account Inbox, claim ESTABLISHED or activate a persistent Account map.

Private import proves the offered route's Account signature and pins its identity;
the issuer prepares its own certificate-owned bootstrap handler when issuing the QR.
Public exchange reuses the authenticated public/reply bootstrap capabilities until
Confirm/Binding ACK completes. No Device/v3 path is involved. Proposed bounds: one
active bootstrap owner per pairing ID, 8 control records / 64 KiB reserved, 24 h max
expiry, identical retry dedupe; excess data rejects without reaching an Account vault.
Bootstrap forwarding still uses normal opaque Node DATA and grants; no special wire
role or clear pairing-control flag is introduced.

`BOOTSTRAP_ONLY` is not `NODE_PREPARED` of the final Account mapping. The provisional
handler and its authority are independently scoped, recorded and retired after final
activation/expiry. A pending bootstrap can stage ciphertext for a locked Account but
must wait for an explicit authenticated Account session to sign/consume relevant
control. Root unlock may relay encrypted retries; it never signs on behalf of a locked
Account. Failure or expiry remains visible and never activates the final map.

Owner tokens must bind a root session, registered stable blind local slot and immutable
route authority capability, not merely a caller-provided migration ID. Activation checks
the staged receipt/digest evidence for that registered owner. A stale-generation token
or arbitrary migration string cannot claim, retire or activate another binding.

## Durable Account mapping and local Node commit

One immutable logical `migration_id` (32 random bytes) identifies this local transfer.
Never reuse it with different immutable contents. Account journal and all maps live
inside Account-encrypted storage; Node bindings/journal use root-encrypted storage.
A stable blind local Account slot is installation-local. Neither it, AccountID nor
migration ID is sent in Node routing frames, discovery KDFs or network mailbox indexes.

Account transaction contains: schema/version, migration ID, owner binding digest,
expected Account signing identity, both bundle digests, old mapping reference, inbound
route/certificate/generation, authenticated peer outbound certificate, receipt bytes,
state and bounded retry metadata. Store inbound index (`local route -> peer`) and
outbound index (`peer -> certified route`) in the **same IndexedDB transaction** with
the journal/active-pointer. Encrypt records before opening that transaction; do not
hold an IDB transaction across WebCrypto awaits. The active pointer references one
coherent generation, never two independent writes as today.

| Durable phase | Meaning / restart rule |
|---|---|
| PREPARED | Authenticated candidate + old references persisted; old map still active |
| NODE_PREPARED | Node independently persisted exact owner/certificate generation; not advertised or dispatchable |
| ACCOUNT_COMMITTED | Both Account indexes and journal/active pointer atomically committed; submission remains blocked pending Node proof |
| NODE_ACTIVE | Idempotent Node activation proves same migration/binding digest; queue/dispatch enabled |
| VERIFIED | Account decrypt/verify/persist through new route demonstrated; legacy records still retained |
| LEGACY_RETIRING | Explicit old-owner revocation/migration task; failed remote cleanup remains visible |
| COMPLETE | Local durable checks and required remote migration receipts present; retention rules still apply |

Across databases there is no fictional global atomic transaction. At every use, the
adapter requires matching Account active pointer **and** Node ACTIVE acknowledgement
for the same owner/binding/migration digest. Crash after ACCOUNT_COMMITTED before
activation means temporary unavailable, then idempotent resume. Crash after Node
activation before acknowledgement recovers by querying exact digest, never by creating
new keys or blindly rebinding. Pending inbound ciphertext may be held but not dispatched
under an uncommitted/wrong Account map. Abort restores old active pointer only when
still in a safe uncommitted phase; after commit use explicit resume/rollback records.

Capture Account key object, blind salt, signing identity, boot attempt and host/root
session token before awaits. Recheck before every storage write, host mutation and
visible success. A late completion cannot attach Account B after switching from A.
Root lock invalidates all owner tokens; Account logout invalidates its mutation token
while preserving committed Node bindings, neutral requests and foreign transit.

Proposed **local-only** host API, agreed directionally with Node agent, not implemented:

- `prepareLocalBinding(ownerToken, migrationId, bindingDigest, expectedGeneration,
  certificate, recipient/discovery private material)` → durable opaque preparation handle.
- `activateLocalBinding(ownerToken, handle, accountCommitDigest)` → ACTIVE proof/queryable
  tuple. Host must authenticate the local owner's registered capability and check exact
  immutable contents; caller-provided string IDs alone confer no authority.
- `queryLocalBinding(ownerToken, migrationId)` → bounded state/digest metadata.
- `retireLocalBinding(ownerToken, handle, expectedGeneration, replacementDigest)` →
  durable retirement result, preserving queued data until authenticated migration policy.

Token creation/registration is root bootstrap's responsibility. Private arrays are
consumed/zeroed as current host APIs do. Local tokens are process capabilities, not
protection against arbitrary same-origin compromise. Existing host `bindLocal` cannot
stand in for prepare/activate/retire; it binds immediately and rejects duplicates.

## Legacy pairing V1 and mailbox migration

V1's Account ID/contribution and v3 derived locator are not a signed V2 bundle. Keep
all old peer/history/key/ciphertext records. Mark `UPGRADE_REQUIRED_V2`; request a
fresh authenticated V2 exchange with the already pinned Account identity. Do not
manufacture a V4 certificate by reinterpreting the V1 contribution or importing an
arbitrary self-signed certificate. Failed/missing V2 exchange remains visibly unavailable
in v4-selected mode; no automatic DeviceClientV3 fallback.

A previously authorized legacy session may remain explicitly labelled legacy migration
mode until its individual upgrade commits. Changing a stored version flag is not a
proof of migration. No bulk cutover, identity regeneration, history rewrite or old
ciphertext deletion is permitted as a shortcut.

Network mailbox transfer is owned by the Node migration contract: prove both old
owner and new authenticated Node owner with a fresh session-bound transfer transcript,
idempotent ID and durable progress. Account commit must wait for confirmed destination
ownership/readability when old queued ciphertext is in scope. A route-binding receipt
alone cannot authorize access to an old mailbox. Account history/storage backups and
rollback compatibility must be checked independently of Git revision rollback.

## Public Request / Accept / Confirm over the same Node

Public route certificates remain root-owned and are not bound to an active Account.
A neutral request dispatcher consumes only records addressed to a public local owner;
it never inspects foreign transit. The recipient envelope hides request type from the
network; local plaintext request contains no AccountID/key until explicit acceptance,
preserving the existing first-contact privacy boundary.

Define `CONTACT_REQUEST_V2`: stable request ID, expiry <=24 h, display name <=128
UTF-8 bytes, introduction <=4096 bytes, authenticated reply DiscoveryCertificateV4,
bootstrap box key, supported exact transport/pairing profiles, fresh request nonce.
A signature under the reply route authority binds canonical request bytes. This proves
control of the reply capability, not Account identity/human identity. Request retries
reuse identical bytes, expiry and ID. Bound encrypted pending storage by total bytes,
per-route/global counts and TTL; proposed defaults 64 total requests, 16 per public
route, 1 MiB global, 24 h. Limits must be shared fixtures, not UI-only checks.

Neutral dispatch API: root owner token + opaque public-binding handle; `listRequests`
returns a paginated UI projection only when root-unlocked. `claimRequest` requires a
fresh local Account session capability and expected record digest, then writes one
idempotent claim. It does not decrypt an Account vault or select/login an Account.
Locked/unselected Accounts cannot accept implicitly. Decline persists a local tombstone;
expiry/repeated clicks/replay cannot resurrect it. Unknown or malformed records are
isolated/quarantined and cannot starve valid following requests.

After explicit Account selection, `CONTACT_ACCEPT_V2` carries selected Account's signed
pairing V2 response, original request digest, fresh `accept_bootstrap_box` (32-byte X25519 public key),
accept expiry and an Account signature over all of these fields. It is encrypted
to the request's bootstrap box key and sent through its ordinary certified reply route.
The requester verifies exact outstanding request and reply capability before accepting
that Account identity. `CONTACT_CONFIRM_V2` carries requester's signed V2 bundle and
receipt over request+accept+both bundle digests, encrypted to the acceptor's bootstrap
material. The acceptor cannot sign a final binding before learning the requester's bundle.
It returns `CONTACT_BINDING_ACK_V2` with the second binding signature after validating
Confirm; this is an automatic idempotent response to Confirm, not a fourth user action.
Lost ACK causes an identical Confirm retry and identical cached ACK. The final
two-signature binding receipt enters the same journal/activation flow as private pairing. No NODE_ACCEPTED return means contact established. Durable
request/accept/confirm retry is scoped to original Account/session and exact bytes;
locking/switching never routes the operation into another Account's vault.

Public bootstrap material is ephemeral, expiry-bound and root/account ownership is
explicit. Network packets contain opaque recipient envelopes only. Request bodies,
Account keys, request IDs and local owner/claim tokens do not become Node wire labels,
mailbox keys, DNSS or logs. Node public dispatch is a local delivery API, not a new
wire role or endpoint-only network operation.

## Failing regression harness and acceptance matrix

`tools/diagnose_node_account_v4_contract_gaps.cjs` runs current production modules with
real NaCl certificate signatures and fault-injected in-memory persistence. Default
exit 1 means the proposed contract is not met. It is intentionally separate from the
green default suite until corresponding implementations are reviewed. It demonstrates
unsigned peer/certificate association, torn mapping writes, and generation rollback.
It is UNIT diagnostic evidence, not browser/transport acceptance.

Required implementation tests: canonical vectors/signature field mutation; wrong
Account/certificate/profile/time/target; certificate substitution; old generation and
same-generation conflicting digest; identical retry; both receipt orders and missing
receipt; restart at every journal transition; failure of each IDB write/commit;
Account/root change during each await; stale owner token; Node ACTIVE/Account pointer
mismatch; two Accounts receiving while one is locked; public request without login;
claim collision, poisoned first request, bounded pagination and quotas; V1 upgrade
required/no v3 call; wrong old/new mailbox owner and repeated transfer; retained old
ciphertext/history and rollback.

Browser acceptance must use ordinary QR/contact and Request/Accept/Confirm UI, exact
integrated source/page/SW, real Node WSS and actual two-way Account messages/receipts.
Assert no v3 sockets in v4 mode, foreign transit continues after Account logout, full
root lock closes runtime, and newly selected Account never receives another's pending
payload. Unit mocks or manual Core attachment cannot satisfy these gates.

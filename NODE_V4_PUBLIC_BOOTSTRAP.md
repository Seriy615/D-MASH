# Public neutral bootstrap: next implementation contract

Status: implementation draft, not enabled in ordinary UI; real browser acceptance
has a bounded mechanism PASS (details below), not ordinary UI acceptance. Private bootstrap checkpoint 382db71 is not this path.
This design extends the same opaque recipient transport; it adds no wire role,
endpoint operation, Account identifier in labels, or v3 fallback.

## Root capabilities and durable ownership

A root-owned registry creates two explicit local kinds: PUBLIC_INTAKE and
PUBLIC_REPLY. Both have independently generated route signing, discovery signing,
discovery box and recipient box material; an additional ephemeral bootstrap box
is bound into the public request/accept transcript. Keys are encrypted under a
separate root-derived store key and restored unchanged after root unlock. No
Account private material is supplied. Caller strings are not owner capabilities:
Host returns a private branded handle only for a genuine live Worker registration.
Root lock invalidates handles. Reopening a stored registration remints a new handle
against its authenticated encrypted row, preserving its certificate and keys.

The exported public descriptor binds the exact certificate and explicit public
bootstrap profile. A recipient route certificate is pinned before sending. A
private or ordinary final route cannot be silently reclassified as PUBLIC_INTAKE.
PUBLIC_REPLY is bounded and expiry-scoped; it is not an Account final route.

## Canonical request

`CONTACT_REQUEST_V2` has exact fields: type, version, request_id, target_digest,
issued_at, expires_at, display_name, introduction, reply_certificate,
bootstrap_box, profiles, nonce, signature. Version is 2. IDs/digests/nonces are
32-byte lowercase hex. The bootstrap box is strict X25519. The target digest is
SHA-256 of the canonical target certificate. Profiles is the exact ordered list
`["NODE_TRANSPORT_V4", "DMASH_PAIRING_V2"]`; no downgrade negotiation is inferred.
The signature is Ed25519 by reply_certificate.route_id over the domain-separated
canonical unsigned object. Strict discovery key/signature encoding checks apply.
This signature proves possession of a reply capability only.

Times are nonnegative safe integers. Expiry is at most 24 hours from issuance and
bounded by both target and reply certificate expiry. Display name and introduction
are limited to 128 and 4096 UTF-8 bytes respectively. Exact canonical serialization
and full recipient-envelope expansion must fit before any transport mining starts.
Unexpected fields, alternate encodings, malformed keys, signature substitutions,
wrong target and expired controls fail closed.

## State and human actions

Intake stores an authenticated request in the root-neutral encrypted queue, including
its exact original bytes and digest. Request receipt does not select an Account.
Limits are 16 requests per public route, 64 total, 1 MiB total serialized contents,
with durable replay/tombstones. Same ID and exact bytes are idempotent; conflicting
reuse is refused. Malformed unrelated rows cannot starve valid entries. A selected
expired request remains an explicitly expired intent until local dismissal.

Listing uses the root handle and exposes a UI projection. Claiming requires a genuine
live Account owner capability, the request digest and the selected Account's valid
local signed bundle A. Claim is an immutable durable association to that owner and
bundle; cancellation/Account switch never moves it into another Account. Claim does
not replace the root-neutral record with an Account contact or final route.

`CONTACT_ACCEPT_V2` carries the exact request digest, bundle A, accept bootstrap box,
reply context and expiry, signed by A. It is encrypted to the requested bootstrap
box and then transported through the certified ordinary reply route. The requester
checks its outstanding request and both encryption contexts before displaying A as
an unconfirmed candidate. It does not trust a merely arriving Account public key.

Explicit confirmation creates targeted bundle B. `CONTACT_CONFIRM_V2` binds request,
accept and both bundle digests and contains B's Account signature. If B is the lexical
first signer, it also carries the journal-reserved ACCEPT binding receipt. Otherwise
A responds with its ACCEPT receipt and B returns CONFIRM automatically. The completed
receipt exchange is acknowledged idempotently without another human action. Both
bundles are available before the bilateral receipt prerequisite is imposed.

Every retry preserves original signed bytes. Stable sealed ciphertext requires a
durable prepared-envelope record and is not implied by a raw send helper. Root-neutral
records retain request/claim/accept/confirm and receipt state until ordinary Account
journal commit and genuine Host activation complete. Bootstrap processing cannot mint
an Account commit receipt, advertise a final ACTIVE map, or declare ESTABLISHED.

## Acceptance gates

Real Worker/Python traffic must show intake without Account login, unchanged transit
behavior, durable restart/replay quotas, wrong target/signature/size/expiry rejection,
Account switch/claim isolation and both lexical signature orders. Real UI then covers
public QR sharing, import, request, Account selection, accept, confirm, key confirmation
and bidirectional messages. Codec tests alone and private-route tests satisfy none of
those public UI gates.

## Current draft API and review limits

The separate local profile is `public-v1`; `private-v1` remains accepted unchanged.
Host calls are `registerPublicBootstrap`, `releasePublicBootstrap`, `publicRoutes`,
`publicRequests`, `sendPublicRequest`, `declinePublicRequest`, `claimPublicRequest`
and `submitPublicControl`. Every root registration returns an opaque capability.
Listing is bounded to sixteen records with an optional request-ID cursor; results
omit bootstrap private material and prepared transport blobs. Worker RPCs with a
PUBLIC prefix use the Host's private dispatch permit. Requested profile mismatch
fails closed when a stale Worker is loaded.

The draft saves the sealed recipient envelope before discovery/submission. Retrying
an existing operation checks the immutable request/claim/control context and reuses
its stored envelope. Certificate and signed-control expiry are checked again after
discovery immediately before send. Quotas apply to accumulated control records,
not only the first request text. Expired unselected records may be removed; claimed
expired intent remains bounded retained state. Renewing registrations and dismissing
claimed archive state require explicit later lifecycle work.

A duplicate Confirm may retransmit the already persisted signed receipt envelope
without generating a signature or opening an Account vault. This is a root-owned
cached protocol response for that immutable exchange, bounded by its original
expiry. A duplicate ACCEPT binding receipt may similarly trigger its already stored
CONFIRM response. Account switch cannot select a new owner or alter these bytes.
This background replay behavior requires integration review with Account orchestration.

Current tests distinguish pure codec/real encrypted in-process journal acceptance
from the pending real two-Worker/Python browser test. None demonstrates ordinary UI,
final Account journal activation, N4 E2EE key confirmation, or full N3 completion.

## Browser mechanism evidence, 2026-10-08

Corrected fixture78498 exited0: two real browser Workers via a Python Node, neutral
REQUEST without Account, genuine owner claim and signed ACCEPT/CONFIRM/bilateral
receipts, then root lock/reopen preserving Node identity and public journal.
Manifest records base62f97d7 plus WIP with78 SHA256 source hashes; none changed
during the run. This is precommit evidence, not an exact committed SHA PASS.
The fixture uses synthetic KEM bundle bytes; it does not prove Account KEM/session
handshake, final mapping activation, user inbox, public UI or all recovery cases.
Earlier two runs failed because async waitForFunction stopped polling too early;
corrected harness uses bounded awaited page.evaluate. Both failed logs retained.

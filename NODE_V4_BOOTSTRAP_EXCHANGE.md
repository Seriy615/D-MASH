# Local bootstrap control exchange — implementation boundary

Status: proposed dispatcher slice; ordinary UI/public bootstrap and full N3/N4
remain incomplete. A dispatcher that requires two bundles before accepting the
second bundle is circular. Therefore bundle intake and bilateral receipt dispatch
are distinct authenticated control stages, with explicit local user selection.
No Account signing/E2EE secret goes to Worker or transit. Signed public bundles
and local recipient envelope keys may go to the local Worker; all mesh payloads
remain opaque recipient envelopes.

## Private imported-offer path, complete dependencies

A creates its signed pairing bundle A and retains certificate/route material under
root ownership. Its imported QR gives B bundle A and its public certificate.
Before publishing QR, A must explicitly provision a bounded bootstrap route for
that certificate. It receives REQUEST candidates without an active Account map.
B has its own Account unlocked, creates signed bundle B targeted to A, and prepares
its own bounded bootstrap route BEFORE sending REQUEST. Both route material sets
are independent of Account E2EE secrets.

REQUEST contains exchange ID, exact target bundle A digest, signed bundle B and
expiry, all signed by B's Account key. B already knows both bundles. A's bootstrap
intake needs only local bundle A to validate target/context and B's signature/bundle;
it does NOT require a bilateral candidate first. B remains an unaccepted identity
candidate until A selects Accept. Intake never activates a route map or delivers
REQUEST into an arbitrary active Account. It stores a bounded pending projection
under the issuing owner's blind bootstrap slot. Denial/expiry leaves a tombstone.

After A explicitly accepts B, local Account journal stages both bundles and pins
identity/contribution/certificate association. Now BOTH sides can reconstruct the
same binding digest using existing binding codec. ACCEPT and CONFIRM controls
carry exact exchange/target/request digests and signed bilateral receipts, not
arbitrary payload strings. Transit never sees these control types.

Receipt phase names belong to lexical signer ordering, not UI actor ordering.
Current codec requires ACCEPT from the lower signing identity, then CONFIRM from
the higher signing identity after verifying ACCEPT. Therefore:

- If B is lower, REQUEST includes B's durably reserved ACCEPT receipt (B can
  derive the binding before send). A validates it only after reconstructing both
  bundles and explicit acceptance; A's transport ACCEPT returns its CONFIRM receipt.
- If A is lower, REQUEST has no premature CONFIRM receipt. A's transport ACCEPT
  carries A's ACCEPT receipt; B's transport CONFIRM carries B's CONFIRM receipt.

Transport CONFIRM always signals B's explicit UI confirmation and repeats both
verified receipts once available. In the first branch it repeats the already
received second receipt; no new signature is needed. A returns an idempotent control
completion response. Retries reuse exact IDs/bundles/receipt bytes; crossed offers
remain journal-controlled, not resolved by bootstrap arrival order. Ordinary
Account mapping activation still requires genuine Host PREPARED proof and durable
four-row Account commit receipt on each side. Bootstrap dispatch cannot call
activate or manufacture that receipt. ESTABLISHED still needs N4 key confirmation.

## Public neutral path is different

The existing accepted contract forbids Account identity in the initial public
request. Do NOT substitute the private REQUEST above for public first contact.
Public CONTACT_REQUEST_V2 is signed by an independently owned reply route key,
contains a reply certificate/bootstrap box and neutral text, and enters a root-owned
neutral queue without Account login. Explicit local Account selection produces
CONTACT_ACCEPT_V2 containing selected bundle A plus request digest and an ephemeral
reply capability. Only then does requester reveal signed bundle B in
CONTACT_CONFIRM_V2. That message delivers the second bundle; the acceptor can now
reconstruct binding and issue/return the required lexical receipt. When signer order
requires the requester to sign first, Confirm includes its ACCEPT receipt; otherwise
additional automatic receipt exchange follows, with stable bytes and no extra user
action. The return capability exists before this exchange, so no final ACTIVE map
is assumed. UI naming must not confuse these messages with lexical receipt phases.

Public reply capability authentication, durable neutral claims and these control
envelopes are separate required codecs/integration. The upcoming signed-receipt
Worker dispatcher alone does not implement them. A useful first slice validates
REQUEST second-bundle intake plus receipt phases for the private imported-offer
path; public path must stay NOT IMPLEMENTED, with no v3 fallback.

## Independent bootstrap state and bounds

The same certificate may temporarily resolve to an explicitly provisioned
BOOTSTRAP_ONLY handler. This is separate from final NODE_PREPARED/ACTIVE mapping:
only verified allowlisted controls enter a separate blind bootstrap inbox. Pending
final binding does not deliver user ciphertext. Bootstrap dispatch validates
recipient envelope, exact canonical control schema, local target/exchange digest,
signature, expiration and immutable peer selection before persistence.

Initial limits: at most8 pending REQUEST candidates per local bootstrap binding,
32 globally; each REQUEST must fit the existing16384-byte sealed recipient envelope, including JSON escaping/wrapper and72-byte cryptographic overhead (not a16KiB plaintext allowance), total pending encrypted plaintext <=128KiB;
at most4 receipt/completion controls per selected exchange, each<=4KiB and aggregate
<=8KiB; An intake reservation lease may last120 seconds; it is NOT the human acceptance deadline. Signed exchange/pending validity lasts until the unchanged signed request expiry (at most24 hours and never beyond either bundle/certificate). Losing a short lease permits retry of identical bytes. Expiry preserves a truthful expired intent until UI dismissal/reissue; a fresh offer requires explicit new signed bytes and exchange ID, never silent renewal. One
owner cannot monopolize other owners' quota. Duplicate exact bytes are idempotent;
conflicting reuse of exchange/phase fails. Count/replay reservations and persistence
must be durable atomically, or crash/reload would reset the quota. Expired/denied
records retain bounded replay tombstones until their signed validity ends. A
malformed record is isolated and cannot starve valid following requests.

Promotion requires verified candidate plus explicit owner/Account guard; there is
no automatic identity pin on REQUEST signature success. Account logout revokes
mutation handles but leaves root-owned committed Node/transit alive. Root lock
closes dispatcher and clears private bytes. Reactivation restores encrypted state
and the same generation, never regenerates identity/route keys to pass a test.

## Expired local intent archive capability (implementation draft)

Normal owner registration still requires a currently valid certificate. A separate
`challengeArchivedOwner(accountPublic, certificate)` checks an expired certificate
cryptographically at `expires_at - 1`, derives the same root-bound blind owner
slot, and requires an exact certificate/Account/slot commitment match in an
existing encrypted final ownership row or bootstrap configuration. A fresh
Account signature over the root-session challenge is still mandatory. This is
historical local access, not renewed network authority; an absent route cannot be
created through this API.

The resulting capability permits local bootstrap listing, ownership queries and
Inbox list/ACK only. ACK follows Account durable persistence as usual. Discovery,
submission, provisioning, selection, preparation, activation and retirement all
reject archive capabilities. Root reload retains selected expired intent but does
not advertise the expired bootstrap route. Certificate renewal and authenticated
higher-generation migration remain separate unfinished work. Browser evidence
must distinguish retained selected control intent from final user-message drain;
a unit test of the latter does not imply browser or ordinary UI acceptance.

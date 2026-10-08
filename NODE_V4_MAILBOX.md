# Universal v4 mailbox contract — proposed, not implemented

Scope: development plan §4.5/N3. This is a review boundary, not a claim that
ordinary Accounts or either Node runtime already has durable v4 forwarding.
The inactive lifecycle coordinator is unrelated to mailbox authorization.

## Current implementation and concrete failures

`node_routing_v4.py` queues are RAM only. `_flush` removes rows before awaiting
send; `_remove_peer` deletes remaining rows and all associated labels. Routes
retain the exact old channel object. A new authenticated session is therefore
insufficient to replay a queued old label. A persistent queue alone would either
remain unusable or misdeliver through a reassigned label. Browser routing has
the same integration obligation; a Python-only store is not completion.

`node_relationships_v4.py` already persists encrypted directional relationship
material under a Node-bound protected key. It rejects an unexpected new inbound
DNSS. These records establish continuity, not live authorization or route rights.
`dnss_mailbox.py` provides useful SQLite lease/quota algorithms, but its v3 wire
frame and caller-supplied alias are not a v4 authorization contract.

## Owner and grant

A mailbox belongs to the authenticated recipient Node AND a confirmed directional
store grant issued by the storing Node. The grant binds version, issuer Node,
recipient Node, exact directional relationship commitment, unpredictable grant
identifier, generation, policy/quota and expiry. A NodeID or DNSS by itself is
never sufficient. Grant issuance follows fresh NODE/password admission and
explicit local store policy; membership grants no arbitrary route ownership.

The recipient proves current possession through the fresh authenticated channel;
the storing Node verifies its issued grant and relationship direction, validity,
revocation and recipient identity on every bind/drain. Proofs bind the current
transcript and cannot authorize another connection. Storage APIs accept opaque
capabilities minted by that verifier, never caller dictionaries containing
`authorized: true`. Full protocol encoding and Python/JS vectors remain required
before enabling this profile; no unverified ad-hoc operation may be deployed.

Persistent lookup is HMAC under a stable, domain-separated Node storage key over
issuer, recipient and grant commitment, with canonical length-framed input.
Raw DNSS/AccountID are not lookup columns; grant metadata is encrypted at rest.
Do not replace missing keys or reinterpret an old store under a new Node identity.
Storage-key existence checks must include every durable store, not only the
relationship database. No Account keys participate in transit authorization.

## Durable labels and fresh-session rebind

Persist accepted forwarding records with their outgoing peer/grant authority,
opaque ciphertext, expiry, dedupe identifier and immutable route-binding
commitment. Persist route authority separately from executable local callbacks
and socket objects. Discovery-return closures are transient and cannot become
durable mailbox owners merely by serializing their label strings.

After reconnect/restart, the recipient rebinds an authorized stable grant to its
fresh session. An old wire label is never implicitly trusted on that session.
Route-binding continuity must be authenticated by the holder of the corresponding
route capability; a replacement label is accepted only for the same binding
commitment and valid authority. Missing local callback, missing downstream grant,
expired route or incomplete recovery blocks that row until authenticated rebind
or expiry. It must not dispatch into an arbitrary newly active Account.

Store/drain applies identically to transit next hops and locally addressed flows.
Neither the grant nor drain states that the neighbor is an Account endpoint.
No ROLE_DEVICE, endpoint-only PULL, mandatory client ACK or silent v3 fallback.
One universal drain request captures ALL eligible current rows within the
admitted mailbox quota; bounded wire fragments may represent this one immutable
snapshot without introducing pagination that leaves authorized rows unclaimed.

## Transaction and failure rules

1. Validate live capability and grant expiry, then reserve ALL current eligible
   rows in one transaction with an unpredictable lease and bounded deadline.
   Another drain cannot steal an active lease. Expired abandoned leases recover.
2. Await complete send of the snapshot on that authorized session. If fragmented,
   await every fragment before deleting any leased row. Recheck capability before
   each send; logout of an Account is irrelevant, full Node lock invalidates it.
3. Successful send deletes exactly rows bearing that lease and owner. Concurrent
   arrivals survive. Failed send, cancellation or session replacement releases
   the lease and retains ciphertext. Cancellation cleanup must be awaited/shielded.
4. Restart between send and deletion may replay; receiver/Account dedupe and
   durable retries handle it. A successful network send followed by receiver crash
   before receiver persistence may lose that delivery. This is the requested
   send/delete contract, not exactly-once or client-persist confirmation.
5. Expired records are never sent. Expiry/quota/revocation are explicit outcomes;
   avoid silently deleting unexpired ciphertext merely because a peer is offline.

## Owner migration and rotation

Ordinary reconnect preserves grant owner and directional relationship. Rotation
or legacy import requires proof of BOTH old ownership and new ownership, plus a
unique migration identifier and immutable source/destination commitments. Persist
an idempotent migration journal. Repeating the same tuple resumes/returns its
result; reusing the identifier for a different tuple fails. Do not overwrite an
old queue or retire its authority before durable transfer and verification.

If source and destination share one database, copy/rebind and journal publication
can be transactional. Cross-store migration requires durable prepare/copy/verify/
activate/retire stages; do not claim cross-database atomicity. Rollback before
retirement retains old access. After retirement a downgrade must refuse unsupported
state instead of recreating identities or discarding ciphertext. An expired old
grant does not automatically become proof of ownership: recovery needs a separate
explicit authority policy and tests before activation.

## Narrow next implementation and acceptance

Proposed first ownership: new `D-MASH/client/backend/node_mailbox_v4.py` and
`D-MASH/client/tests/test_node_mailbox_v4.py`. Implement persistent encrypted owner
records, strict opaque capability boundary, snapshot lease/send/finish and
idempotent same-store migration. This is inactive infrastructure until real
channel/grant verification and routing integration land together. Existing
`route_discovery_v4.py` and its tests belong to the Account agent and are excluded.
Subsequent coordinated edits are `node_channel_v4.py`, `node_service_v4.py`,
`node_routing_v4.py`, followed by equivalent browser persistence/Worker plumbing.

Meaningful required tests: wrong Node/direction/transcript/grant refused; expired
and revoked grants refused; fresh-session rebind succeeds after process restart;
stale session and label substitution denied; all rows drained with arrivals during
send retained; partial/failed/cancelled send retains every leased row; competing
leases; crash before/after send/delete; migration retry/conflicting ID/old-owner
retirement; key loss fails closed; local and transit use identical operation
shapes. Final real browser acceptance requires offline B in N1→B→N2 without
Account login, restart/reconnect, no bypass, exact deployed SHA and preserved
identities. Unit storage persistence alone is not mailbox acceptance.

### Inactive storage candidate (8 October)

The proposed new Python module and nine storage tests now exist. Tests exercise
real encrypted SQLite, wrong-key/Node reopening refusal, ALL forty-row snapshot,
concurrent arrival, failed send and cancellation retention, lease exclusion and
expiry recovery, stale capabilities, and same-store migration replay after reopen.
Grant and dual-owner proof verification remain explicitly trusted injected
interfaces, supplied by a controlled test verifier only. No production verifier,
wire grant, routing integration or browser durable forwarding is implemented.
The existing routing loss diagnostic remains expected-red. Same-store migration
requires an empty destination and refuses active leases; it does not merge queues
or implement cross-store/legacy migration. Retired-owner fresh bind only permits
verified replay of the exact migration journal; ordinary mailbox access rejects it.

### Review tightening

Owner identity now includes the full canonical grant commitment: issuer,
recipient, direction, grant ID, generation, exact expiry and policy/count/byte
limits. Renewal or policy change creates a distinct owner and requires explicit
migration; it cannot silently reopen an earlier queue. Each encrypted row contains
its immutable route commitment, generation and expiry from the trusted route
verifier. Fresh drain must pass `verifier.rebind` for these exact bindings.

The ALL send callback is a trusted adapter interface `(snapshot, guard)`.
It MUST invoke `guard()` immediately before each fragment and cannot defer
unchecked fragments. Guard checks current/revoked/session authority, record expiry
and route rebind. Store checks before and after the callback too; it cannot enforce
fragment timing inside an arbitrary dishonest callback. Thus no claim of wire
expiry enforcement is made until the real adapter implements this contract.
Records cannot outlive either route binding or grant. Capabilities, owner rows and
migration journals have hard count bounds; release handles to reclaim in-memory
capacity. Journal/retired-owner compaction is deliberately absent: quota exhaustion
fails closed without deleting recovery evidence. Migration enforces destination
policy, lifespan and route rebind as well as the separate dual-owner verifier.

Eleven storage tests pass, including generation mismatch, between-fragment expiry,
revocation, wrong direction, lifetime and metadata limits. Authentication remains
injected and unintegrated; these do not substitute for real channel proof vectors.

Eligibility selection now verifies authenticated row metadata before considering
expiry or routing. Owner, delivery dedupe, byte length and expiry are authenticated
inside each encrypted record and compared with SQLite indexing fields. A modified
index is not trusted to extend lifetime or select a different delivery. Corruption
fails closed; this is not protection from rollback of an entire valid database.
Unexpired records whose trusted rebind verifier raises PermissionError remain
unleased and retained, counted in `last_blocked`; all other eligible rows are
leased and sent. Other verifier faults abort rather than silently classifying bugs
as unavailable routes. A binding revoked after selection still aborts that snapshot
and releases its lease; the next selection excludes it. Twelve tests pass including
two bindings with one blocked and SQLite expiry alteration.

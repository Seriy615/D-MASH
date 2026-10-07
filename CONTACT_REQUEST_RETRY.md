# Public Contact Request retry — v3 migration adapter

The initial encrypted ContactTransport envelope is durable before route lookup
or submission. A stable request ID binds the immutable request, destination
certificate and exact initial envelope to one local Account slot. Neither a
failed route lookup nor local Node acceptance removes this intent. An accepted
bootstrap response ends initial retries; no new request ID/ciphertext is minted
for a retry. This does not change the network request schema or claim v4 cutover.

Persist creation time, expiry (24 hours), attempts and next-retry time. Reserve
the next retry before network work; delays start at 5 seconds, double to a
5-minute cap, and permit at most 256 automatic attempts within the expiry.
Regular local sync/reconnect resumes only the unlocked owning Account. A
failure of one request does not stop unrelated requests. Account changes cancel
submission after route lookup. Explicit UI progress distinguishes queued sending,
awaiting acceptance and expired intent; local queue acceptance is not a peer
receipt. Old states without an initial envelope remain readable but cannot be
resubmitted with invented ciphertext.

Acceptance requires offline first send, send=false, lost initial request,
restart with persisted ciphertext/backoff, no cross-Account replay, accepted
bootstrap stopping retries, expired/budget exhausted intents, and a real public
browser flow with one initial packet deliberately dropped. Existing Accept and
Confirm also must treat send=false as failure, retaining their durable controls.
The full Contact/N4 crash/version/confirmation matrix remains a separate gate.

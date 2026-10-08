# Bounded Node discovery retry (candidate)

A recipient that reconnects after a single PROBE previously remained unreachable
until the query's 180-second expiry. Both routing implementations now issue fresh
authenticated discovery queries at 0, 5 and 15 seconds and stop after 30 seconds.
The certified destination stays fixed. Every attempt uses a fresh encrypted query
and return label; superseded local labels are removed. No Account identifiers,
keys or endpoint role are added to the routing wire.

Each runtime allows at most eight concurrent discoveries and 24 locally originated
PROBEs per neighbor per minute. Existing forwarding admission remains independent.
A successful verified reply alone creates the returned route. Timeout, cancellation
and close clear local pending state without closing an otherwise healthy channel.
JavaScript additionally accepts an AbortSignal; Python accepts task cancellation.
Managed LocalDelivery propagates an AbortSignal and aborts pending discoveries
when the Worker releases their owner or closes local delivery. Other owners remain
active. A late result after cancellation cannot mint a prepared grant. This wiring
builds on the existing owner-scoped grant release implementation; no new wire
operation or public owner authorization bypass is introduced.

The remote query TTL remains protocol-compatible. This change does not revoke
already allocated remote labels; those remain bounded by existing hop quotas and
expiry. It does not implement durable mailbox replay or recipient delivery ACK.

Validation: three Python tests and JavaScript fixture verify real discovery crypto,
fresh labels, cancellation, rate refusal and deadline cleanup using accelerated
schedulers. Existing routing/opaque retry regressions are also required. Fixtures
are UNIT evidence, not browser or deployed acceptance. Real Worker/Python recipient
rejoin acceptance is still required before enabling the candidate.

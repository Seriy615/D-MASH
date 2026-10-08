# Managed Account transport integration boundary

Status: inactive modules, not ordinary UI cutover. The managed adapter replaces
its earlier certificate-only `configurePeer` implementation. That API now refuses
with `SIGNED_PAIRING_V2_REQUIRED`; there is no raw mapping or v3 fallback.

Trusted assembly constructs `AccountNodeTransportV4(host, Core, Storage,
{journal, sealedStore, resolveOwner})`. Core provides its committed Account
capability. `resolveOwner(peer, snapshot)` returns actual opaque Host
`{capability, preparation}` objects. The adapter verifies the journal's eight
immutable preparation fields against the live Worker and requires ACTIVE for
outbound use. An arbitrary route-shaped object cannot be submitted.

`readRouteSnapshot(peer)` returns the journal's authenticated historical binding.
`prepareAndSubmitIntent({operationId, frame, peer, bindingDigest, generation})`
requires an already authenticated N4 intent. N4 owns signed frame verification
and must persist its intent first. The sealed store treats the exact frame as
opaque bytes and never changes its signature or fields. It binds the operation
ID, frame hash, peer, binding digest/generation and certificate digest in a
captured-key encrypted record. A successful IndexedDB commit precedes publication
of its recipient envelope; concurrent materializers return the one durable
winner. Retry and reopen reuse the stored bytes. Context changes refuse reuse.

Outbound discovery uses `host.ownerDiscover(capability, certificate)`; transmission
uses `host.ownerSubmitSealed(capability, grantHandle, {certificateDigest, blob})`.
The certificate digest is SHA256(secureSession.canonical(certificate)), explicitly
a local API digest distinct from the pairing codec's ordered wire digest.
`{state: 'LOCAL_NODE_QUEUED', queued: true}` is only local Node acceptance. N4 keeps
its peer-confirmation intent until the protocol confirms it.

The adapter rechecks Account/root guards around each await and current journal
binding plus live Node ownership before submission. A stopped Account cannot
publish new operations. It does not claim global atomicity across the Account
and Node databases. A full external database rollback remains outside local CAS.

The new managed inbox passes verified peer/local-route
context to N4's `receive({peer, frame, localRouteId})` and acknowledges only after
`persisted: true`, under the same captured Account capability. Read/acknowledgment
of a retained mailbox under an expired certificate needs the separate read-only
archive owner capability; outbound ACTIVE permission must not be reused as a
condition for reading retained history.

`AccountSessionRuntimeV4({core, transport})` is the Account-only N4 owner. Trusted
assembly calls `openPeer(peer, {requiredSuite: AccountHandshakeV4.SUITE})`, then
`initiate`, `receive`, `resume` and `status`; it may start the bounded retry timer.
It loads an encrypted AccountSessionStoreV4 ledger for the signed journal binding.
`OWNER_ACTIVATE` / route `ACTIVE` only proves the Node owns that route. The chat
must remain key-pending until `status(peer).phase === 'ESTABLISHED'`, which occurs
only after the signed INIT/FINAL/CONFIRM/CONFIRM_ACK sequence and key confirmation.
The runtime never calls a v3 fallback. After reload, trusted assembly must
rehydrate each committed peer and call `openPeer` before `resume`; `resume` does
not enumerate encrypted Account peer records itself.

Verification: focused adapter unit uses real NaCl signatures/recipient encryption
with mocked Host and journal; sealed-store Chromium fixture uses real signed
binding, AES-GCM and IndexedDB. The separate Worker/Python transport fixture passed real owner discovery,
recipient decryption, exact ciphertext retries/reopen, one recipient delivery
after replay deduplication, and Account abort with the same Node alive. Evidence:
`docs/evidence/2026-10-08/qa-account-media-managed-adapter.json`. Managed inbox
currently has unit coverage; actual N4 inbound and ordinary UI remain separate
acceptance gates.

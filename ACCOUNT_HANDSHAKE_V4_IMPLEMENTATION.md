# Account handshake V4 implementation contract (inactive draft)

The only implemented suite is `X25519_LEGACY_KYBER768_HKDF_SHA256_V1`.
It explicitly uses the existing bundled Kyber768 artifact; this name is not a claim
of ML-KEM conformance, PQ, PCS or reviewed production readiness. No classical or
legacy-frame fallback exists. Existing static Account keys are not replaced.

Canonical frame field order and per-kind limits are defined by
`account_handshake_v4.js`. Ed25519 signatures use
`D-MASH|ACCOUNT-HANDSHAKE|V4|<kind> NUL || u32be(length) || canonical unsigned JSON`.
All input signing identities are pinned externally by the authenticated contact.
Account frames remain inside the recipient-encrypted payload, never Node metadata.

INIT contains fresh X25519 and fresh bundled Kyber public material. FINAL contains
fresh responder X25519, Kyber encapsulation and nonce. The session digest hashes
length-delimited canonical signed INIT and FINAL core (init digest, ephemeral,
capsule, nonce). HKDF-SHA256 uses this session digest as salt, input
`u32be(32)||X25519_shared||u32be(32)||Kyber_shared`, and separate root/final/confirm/
ack domains. Every confirmation MAC authenticates the session and preceding frame
digests; FINAL, CONFIRM and CONFIRM_ACK are also signed. All-zero X25519 fails.
Kyber implicit rejection is resolved by mandatory key confirmation, not a fallback.

## Recovery proposal and authorized INIT

A recovery proposal is a signed INIT with `authorization:null`, fresh attempt,
ephemeral/KEM keys and nonce, and the proposer's last-known predecessor/generation.
It cannot replace a confirmed session. RECOVERY_REQUEST binds this proposal digest
and a fresh request nonce. The proposal and private attempt material are durable
before either frame is submitted.

The authority verifies request/proposal correspondence and pins, but does not treat
a stale claimed predecessor as authority. It issues one durable ten-minute challenge
containing the exact request/proposal digests, request nonce, fresh challenge nonce
and ticket, its actual confirmed predecessor/generation (null/zero before any
confirmation), and proposed next generation. The challenge frame's own predecessor
and generation match these asserted values. Replayed requests receive the same live
challenge; they cannot allocate unlimited challenges or change a confirmed root.

The requester verifies that the challenge refers to its durable outstanding request
and proposal. It creates a *new signed authorized INIT* with the same attempt,
identities, binding, suite, ephemeral key, Kyber key and proposal nonce. Its predecessor
and generation now match the challenge authority; its authorization is the challenge
digest. Its new signature covers these changes. RECOVERY_PROOF binds the exact
request/challenge/authorized-INIT digests and ticket. Both exact frames are persisted
before submission; no header is implicitly reinterpreted.

The authority receives/stages the authorized INIT only under its matching live
challenge. It compares all immutable proposal contributions and full context, then
validates the proof against its durable unused ticket. Ticket consumption and pending
FINAL/root are one transaction. Identical proof resumes the exact durable FINAL;
a different proof/INIT cannot reuse the ticket. Missing pending state after consumed
ticket produces an exact signed REFUSE referencing the proof. The requester records
REFUSED; explicit retry after a five-second cooldown starts a new challenge workflow.
The consumed ticket never regenerates FINAL.
Only normal FINAL/CONFIRM/ACK establishes the replacement and advances the ledger.

The ledger, challenge/ticket and replay tombstones occupy a separate encrypted row
from active/pending session secrets. A third encrypted Account/peer binding pointer records the current binding. All
three rows are written by one compare-and-swap IDB transaction in `pairing_material`.
Ledger/state HMAC aliases include the authenticated binding digest and generation;
the stable blind pointer detects replacement bindings before empty new aliases can
be mistaken for a new session. A changed binding fails BINDING_MIGRATION_REQUIRED
and preserves every old row; authenticated migration is a separate explicit step. Missing
state with an intact ledger enables recovery; ciphertext corruption is an error,
not an empty session. A complete rollback of all records is not prevented here.
Existing contact/history stores and legacy session records remain untouched.

## Current acceptance limits

Real crypto UNIT and real Chromium/IDB mechanism fixtures are available. Ordinary
Core/UI integration, real Node transport recovery, session-bound ratchet updates,
and full fault/compromise acceptance remain incomplete. No production activation.

## Retry and local lifecycle

A per-peer operation is serialized; the entire ledger/state update and outbound
intent are persisted before queue submission. Retry reserves attempts before send,
uses 5-second to 5-minute backoff, at most32 sends and24-hour frame expiry. Expired
pending state becomes EXPIRED with a replay tombstone; fresh randomness requires
explicit retry after cooldown. Required-suite refusals remain REFUSED without an
automatic downgrade. Confirmed roots/history are preserved throughout failure.

`flush({submitIntent})` supplies `{operationId,frame,peer,bindingDigest,generation}`.
The supplied trusted Account transport must durably materialize the recipient box
under operationId before its first Node submission and reuse its exact bytes. A
changed certificate must fail explicitly, never reseal an existing operation. The
N4 module does not itself claim exact outer-ciphertext replay before this adapter
is integrated. Tests currently prove exact signed-frame replay and actual recipient
JSON-escaping+72-byte overhead within the existing16KiB limit.

All asynchronous boundaries recheck the captured owner. The real IDB store captures
AES/HMAC keys and DB, aborts its live transactions synchronously on Account/root
signal, encrypts before opening transactions, and compares all three previously read
ciphertext rows before writes. JavaScript secret-field deletion and byte-buffer
clearing do not imply guaranteed physical memory erasure.

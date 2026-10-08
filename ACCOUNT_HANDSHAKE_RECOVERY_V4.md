# Account handshake and authenticated recovery v4

Status: **PROPOSED / NOT IMPLEMENTED**, 8 October 2026. This is an N4 contract
for review after the `.25` UI/identity bugfix checkpoint. It does not activate new
frames, change Core/ratchet, complete N3–N8, or certify PCS/PFS/PQ. Network protocol
version remains Node v4; the version below belongs to the opaque Account payload.

## Reproduced current behavior

`tools/diagnose_initial_handshake.cjs` currently reports H1/H2/H3 PASS. Its H2
asserts only that B emits something after A loses `blind_secrets`; B still owns a
pending old final, so resending that obsolete final satisfies the assertion. That
is not successful recovery into a shared confirmed session.

`tools/diagnose_account_recovery_v4.cjs` strengthens the preconditions using real
bundled NaCl, Kyber WASM and Argon2, with only storage/network faults modeled:

1. Establish and deliver the actual encrypted confirmation, prove B retired its
   pending final, erase only synthetic A's peer session, then deliver A's freshly
   signed init. B consumes it without any recovery challenge/response: FAIL.
2. Leave B's old final pending, erase A's session and replay the returned response.
   The obsolete attempt's final cannot complete A's new attempt: FAIL.
3. Duplicate init while B's final is pending. Kyber capsule stays identical but
   final ciphertext is rebuilt with a new nonce rather than replaying one durable
   frame: FAIL against the exact-frame retry contract.

Evidence: `docs/evidence/2026-10-08/qa-account-media-n4-existing-baseline.log` and
`qa-account-media-n4-recovery-gaps.json`. The latter records source hash and Node
version. These are UNIT diagnostics, not browser or deployed acceptance. The
intentionally red diagnostic stays outside the default regression suite until its
corresponding implementation is reviewed.

Current `staticShared` is populated on both pending and confirmed paths; it cannot
serve as an ESTABLISHED flag. Existing attempt IDs/capsule retention/collision fixes
are useful foundations. Existing ratchet per-peer serialization, update/ACK intent
persistence and two previous epochs also remain foundations, not full recovery.

## Authentication and persistence boundaries

Pinned Account signing identity comes from an authenticated existing contact or
[N3 pairing V2](ACCOUNT_NODE_V4_MIGRATION.md). A signature under an arbitrary key
supplied by the incoming frame cannot replace that pin. N3 route-binding digest and
generation bind this exchange to its authenticated peer relationship. Route READY,
NODE_ACCEPTED and local `staticShared` never establish an Account session.

Maintain three distinct encrypted records under the same Account ownership:

- Contact authority: pinned signing key, authenticated static bundle, N3 binding
  digest/generation, negotiated minimum protocol/profile policy.
- Session ledger: current confirmed session ID/generation, retired session digests,
  recovery challenge state and used-ticket tombstones; survives loss/replacement of
  the active ratchet state when that narrow failure is recoverable.
- Session state: explicit phase, attempt/session IDs, transcript digests, pending
  and confirmed roots, ephemeral secrets, exact outbound frames, retry metadata,
  message counters and bounded previous receive roots.

Never store AccountID or these IDs in Node wire labels, DNSS, route KDF, mailbox
lookup or logs. All handshake/recovery/control frames are opaque recipient payloads
queued identically to other Node DATA; transit needs no Account keys.

Capture Account keys object, blind salt, signing identity, boot attempt, explicit
peer ID and host/root session token before every asynchronous operation. All state
writes, crypto completion and send callbacks recheck this captured owner. A selected
chat is not an operation destination. Root lock cancels; Account logout prevents
new signing/decryption but leaves durable ciphertext intents available for that
Account's later authenticated resume. No late completion writes another vault.

## Versioned frames and transcript

Use an exact schema `type:ACCOUNT_HANDSHAKE`, `version:4`, mandatory recognized
`suite`, `kind`, `binding_digest`, `binding_generation`, `session_generation`,
`attempt_id`, ordered sender/recipient signing public keys, issue/expiry, previous
confirmed session digest (nullable only for initial pairing), kind-specific body,
and Account signature. Unknown fields/versions/profiles reject before expensive KEM.
Serialized body ceiling 12 KiB; exact bounds per kind must be fixture constants.

Sign canonical bytes with domain
`D-MASH|ACCOUNT-HANDSHAKE|V4|<kind><NUL>` and length-delimited canonical body. Use one
shared JS/Python encoding/vector implementation; parser reserialization must match
received bytes. Include complete negotiated suite list/selection and N3 binding in
signed transcript. Account identities are inside encryption, not exposed transport
metadata. Every response echoes and authenticates the preceding frame digest.

`attempt_id` is 32 fresh random bytes per new proposal, persisted before first send.
Retransmission never allocates another attempt. `session_id` is a domain-separated
hash of the authenticated transcript and both fresh contributions, not an AccountID,
NodeID or random socket DNSS. Phases:

| Kind | Bound contents / required receiver checks |
|---|---|
| INIT | Fresh ephemeral X25519 public key, supported suite policy, optional recognized fresh KEM public key, proposal nonce, predecessor session, initial/recovery authorization digest |
| FINAL | Exact INIT digest, selected suite, responder fresh X25519 public key, KEM capsule if suite requires it, responder nonce, final transcript hash, responder key-confirmation MAC |
| CONFIRM | Exact INIT+FINAL/session digest and initiator key-confirmation MAC under a separate directional confirmation key |
| CONFIRM_ACK | Same session/transcript and responder MAC under an ACK domain, acknowledging durable peer-confirmed state |
| REFUSE | Signed reference to exact attempt plus bounded reason/version/profile information; never a downgrade instruction |

Signatures authenticate proposed identities and transcript; confirmation MACs prove
possession of the newly derived secret. Both are required. FINAL received without a
matching persisted INIT (or durable resumed equivalent) cannot replace state. A valid
signature does not permit a late final from an abandoned attempt to overwrite a winner.

## Explicit per-peer state machine

| Local phase | Allowed durable action / transition |
|---|---|
| NO_SESSION | Valid pinned initial proposal or local new initiation creates pending state |
| INIT_PREPARED | Persist exact INIT + private ephemeral material before first queue submission |
| RESPONDER_PENDING | Validate INIT/collision/recovery authority; derive pending root and exact FINAL, atomically persist both before send |
| INITIATOR_CONFIRM_PENDING | Validate FINAL and responder proof, persist pending root + exact CONFIRM before send; user send remains unavailable |
| RESPONDER_ESTABLISHED_ACK_PENDING | Validate CONFIRM, atomically publish confirmed session + durable ACK; responder now has peer key confirmation |
| ESTABLISHED | Initiator verifies CONFIRM_ACK and publishes confirmed session; ordinary sends use only confirmed session |
| RECOVERY_PENDING | Keep old confirmed record while authenticating recovery; never overwrite it just because a fresh init arrived |
| EXPIRED / SUPERSEDED | Retain bounded authenticated tombstone; reject stale frames without regenerating keys |

There is no global atomic commit between peers. If ACK is lost, responder can be
confirmed while initiator waits; duplicate CONFIRM resends exact durable ACK. Valid
application traffic for the pending session can be held in a bounded encrypted queue
but must not silently substitute for the defined ACK transition. UI reports waiting
honestly. An ACK queue submission returning false retains ACK intent and incoming
record; NODE_ACCEPTED does not retire peer-confirmation responsibilities.

Persist the pending/confirmed update, transcript and outbound frame intent together
in one Account transaction. Serialize whole operations per Account/peer, not only
crypto subroutines. Encrypt before opening IDB transactions. Never reset history or
`msgCount` during recovery; history belongs to the Account/contact across sessions.
Session/epoch identifiers namespace message IDs and dedupe entries to avoid collisions
with prior session counters.

## Deterministic collision without overwrite

For simultaneous initial proposals over the same binding/predecessor, order proposals
by `(initiator signing key, attempt_id)` using canonical byte order. Both peers choose
the same minimum. Persist the winning transcript and superseded digest before replying;
resend the exact stored winning INIT/FINAL on duplicate losing proposals. Do not derive
or mix roots from both proposals. Repeated click joins the already durable attempt.

For competing recovery requests, the side retaining a confirmed session acts as the
challenge authority. If both peers retain state but request recovery, order request
IDs with the same authenticated identity tie-break, preserve one challenge workflow
and send a signed exact-winner reference. If both genuinely lack session state but
retain contact authority, use the initial collision rule under an explicit fresh
recovery authorization transcript; never guess the old generation from a packet.
Higher generation is accepted only through valid recovery authority, not because its
integer is larger. Delayed finals/confirms from losers or retired sessions reject.

## Fresh signed challenge recovery

Threat: attacker can retain, duplicate, delay and replay old signed frames but lacks
current pinned Account signing private keys. A new valid init alone must not overwrite
a surviving confirmed root; replayed old init is indistinguishable from intentional
recovery until a fresh challenge is answered. The challenge flow introduces no global
periodic refresh and is event-driven/backed off per peer.

1. Losing peer A persists and signs RECOVERY_REQUEST with fresh request nonce,
   candidate INIT digest, retained contact/binding authority, requested suites and
   last-known session digest if available. This request is authenticated but does
   not itself authorize replacement.
2. B validates pinned identity/binding and rate limits, generates a fresh 32-byte
   challenge nonce and single-use ticket, and persists their exact transcript before
   sending RECOVERY_CHALLENGE. It binds A's request nonce/digest, candidate INIT,
   B's actual confirmed session digest/generation, proposed next generation, expiry,
   both identities and selected suite policy. B keeps its current root unchanged.
3. A accepts only a challenge matching its durable outstanding request and candidate
   INIT. It signs RECOVERY_PROOF over the complete challenge and fresh INIT digest,
   explicitly acknowledging B's asserted predecessor. Optional proof under a surviving
   old root may supplement diagnostics; it is not mandatory when that root was lost.
4. B validates its own durable unexpired ticket and A's fresh signature. Atomically
   consume the ticket and persist a recover-authorized pending attempt before FINAL.
   Duplicate identical PROOF resumes/resends that pending attempt; a different INIT,
   peer, binding, suite or predecessor under the ticket rejects. Only successful
   FINAL/CONFIRM/ACK transitions publish the replacement session.
5. Both retain bounded retired-session replay tombstones and only the separately
   approved receive-history window. Old application ciphertext is neither interpreted
   as new session traffic nor erased with historical user messages.

Proposed resource bounds: one live recovery challenge per peer/predecessor, 10-minute
challenge expiry, persisted exponential retry from 5 seconds to 5 minutes, <=32 sends
per request, 24-hour total operation lifetime, bounded global pending count. A duplicate
signed request receives the same live challenge, not unbounded fresh key generation.
An expired request requires a new persisted random nonce after backoff. These defaults
need shared fixtures and explicit UI expiry/retry, not ever-increasing test timeouts.

Replay properties: an old request can at most solicit a new bounded challenge; the
attacker cannot sign the fresh nonce. Old challenges do not match A's new request;
old proofs do not match B's new ticket/predecessor. Used-ticket replay cannot replace
an active session. Session ledger crash recovery is idempotent. Do not claim rollback
resistance after restoring *all* persistent state, including challenge/ticket ledgers,
to a compromised snapshot. Such a loss needs explicit authenticated re-pairing or an
independent trusted anti-rollback source; a new socket/BootID is not such a source.
If identity authority is missing/corrupt, stop recovery and preserve ciphertext for
explicit repair. Stolen signing keys or ongoing runtime control are outside this
recovery guarantee and cannot be repaired automatically by a fresh nonce.

## Ratchet integration and N5 cryptographic boundary

N4 reliability requires fresh authenticated agreement for recovery, but cryptographic
suite activation needs N5 review. Proposed classical suite uses fresh X25519 agreement,
Ed25519 transcript authentication, domain-separated HKDF-SHA256 and the established
recognized AEAD profile. A hybrid suite additionally combines fresh verified ML-KEM
secret with the X25519 result using a reviewed length-delimited/domain-separated
combiner and independent confirmation/message-root labels. Exact profile vectors and
implementation provenance are prerequisites, not inferred from key lengths.

The bundled legacy Kyber profile may be used only as an explicitly labelled migration
profile if policy permits; no automatic classical fallback when hybrid is required.
`HYBRID_MLKEM768_V2` in current ratchet code is a historical label, not proof that the
vendor artifact conforms to ML-KEM. Current random entropy transported under an old
root, even mixed with static-KEM material, is not the required fresh X25519 PCS step.
Do not assert PCS/PFS/PQ from successful epoch increment, retry, or this proposal.

Each future epoch update binds confirmed session ID, prior transcript/root generation,
from/to epoch, exact update ID, fresh agreement material and suite. Preserve current
persist-before-ACK foundation while extending it to the complete session authority.
A stale update from a prior recovered session rejects even when epoch numbers match.
Concurrent update winner and durable exact update/ACK frames are per confirmed session.
Retention must have a documented time and epoch limit matched to delayed delivery;
unlimited old-root/staticShared fallback is not forward secrecy. Stored readable
history and backup keys are independent compromise surfaces.

## Mixed versions, migration and acceptance

New parser must not reinterpret old `0x01/0x03` bytes as v4. A contact's authenticated
capabilities/policy chooses an explicitly supported profile. Legacy v3 Account frames
remain only in a labelled migration mode; v4 session selection never silently falls
back. Unsupported version/suite receives bounded authenticated refusal referencing
the original attempt, when a legitimate reply capability exists. Unauthenticated input
must not create reflection/amplification or reveal local Account state.

N3 BOOTSTRAP_ONLY routes can carry bounded initial/recovery controls before full
Account readiness, but their route authority is not session confirmation. Route
activation receipts and Account key confirmation remain separate journals/gates.
Identity, root, existing contact/history/ratchet records remain until authenticated
migration commits and rollback/readability acceptance passes.

Required matrix: one/two initiators; repeated click; loss/duplicate/reorder every kind;
crash before/after each write and send; lost final/confirm/ACK; one-sided established
loss and pending loss; stale replay request/challenge/proof/final; ticket expiry/reuse;
wrong signer/binding/suite/predecessor; identity mismatch; old session ratchet replay;
Account/chat switch, logout/root lock during every await; poisoned first Inbox record
followed by valid record; storage failure/disk quota; receiver offline/reconnect;
bidirectional messages and receipts after each successful recovery. Existing history
and another Account's keys/history must survive every case.

Unit/model schedules supplement, but do not replace, actual two-browser ordinary UI
recovery with real Node transport, source/page/SW versions, no v3 fallback, visible
pending/error/cancel state and proof of final shared confirmed session. No DONE claim
until this matrix and N5 suite gates have evidence on an integrated exact SHA.

## Proposed implementation ownership and review sequence

No runtime changes are authorized by this document alone. The first isolated slice
is pure parsing/signature/transcript code with vectors, not Core activation.

| Slice | Account-owned files | Boundary and tests |
|---|---|---|
| N3.1 pure pairing | New `js/account_pairing_v2.js`, `tests/account_pairing_v2.test.js`, shared JSON vectors under `tests/fixtures/` | Strict codec, Account/certificate association, pinned identity/generation/expiry validation; zero host/storage calls; mutation, wrong signer, unknown profile and canonical encoding vectors |
| N3.2 local journal | New `js/account_route_migration_v4.js`, `tests/account_route_migration_v4.test.js`; narrow storage transaction helper | Immutable candidate + atomic inbound/outbound/journal pointer; fake durability/crash matrix; host interface injected, no default activation |
| N3.3 binding control | New `js/account_route_binding_v4.js`, controlled changes to `account_node_transport_v4.js` | Bilateral receipt verification and exact retry via BOOTSTRAP_ONLY owner API; generation rollback rejection; adapter no longer accepts bare self-signed certificate |
| N3.4 public controller | New `js/contact_flow_v4.js`, `js/contact_payloads_v2.js` | Neutral request claim from Node dispatcher; Account-signed accept/confirm/ACK; explicit session guard, no implicit login; UI integration separately owned |
| N3.5 ordinary integration | Narrow reviewed `core_engine.js` + loader changes, jointly scheduled with Node/UI owners | Attach selected v4 adapter/consumer at ordinary lifecycle; explicit upgrade/refusal and no v3 fallback; two real UI profiles and preserved legacy records |
| N4.1 frame codec | New `js/account_handshake_v4.js`, `tests/account_handshake_v4.test.js` + cross-language vectors | Versioned signed frames, transcript/hash domains and confirmation framing; no Core hooks, no assumed ML-KEM compliance |
| N4.2 durable state | New `js/account_session_v4.js`, `tests/account_session_v4.test.js` | Per-peer serialized state machine, exact intent+state transaction, crash/reorder schedules, confirmation separation; storage/crypto/transport injected |
| N4.3 recovery | New `js/account_recovery_v4.js`, `tests/account_recovery_v4.test.js` | Signed fresh challenge/ticket ledger and predecessor authority; replay/loss/expiry/collision tests; old session retained until confirmation |
| N4.4 integration | Narrow Core/ratchet adapter changes after N3 and suite review | Same ordinary opaque v4 queue, peer-pinned receipt/status handling, existing histories preserved; real browser fault matrix |

Node agent separately owns root bootstrap, authenticated local owner registry,
BOOTSTRAP_ONLY/pending/active binding states, durable prepare/query/activate/retire,
neutral request queue and universal mailbox owner migration. Account modules receive
opaque owner handles and immutable commit/query digests; they never manufacture
Node authority tokens or directly edit Node encrypted stores. Owner registration
binds root session, stable blind local slot and exact route authority capability.

Before N3.2/N3.3 implementation, freeze a shared local API fixture defining input
schemas, immutable digest calculation, cancellation result, byte-array consumption,
idempotent duplicate behavior and owner/generation mismatch errors. Node ACTIVE
requires an authenticated Account commit capability, not an arbitrary digest string.
The root-session owner registry must validate that capability; this capability is
local-only and does not protect against arbitrary same-origin code execution.

The safe first independent implementation is **N3.1 only**: reusable strict pairing
codec/validator + real signature/certificate vectors, loaded solely by tests until
review. It can ship while runtime remains `.25`, creates no roots/routes/Accounts,
and supplies one stable validated bundle type for both Node and Account modules.
Do not implement receipt transport, ephemeral-key recovery or new suite negotiation
as an ad hoc Core patch before these boundaries and crypto profiles are reviewed.

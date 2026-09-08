# Transport v3 engineering record

## Status and baseline

2026-09-08. Base: `703a5df` on `main`; clean clone, working branch
`transport-v3`. Historical handoffs are evidence of earlier intent, not the
current executable specification. No production acceptance is implied here.

The following inventory was made before implementation:

| Boundary | Executable baseline | Target delta |
|---|---|---|
| Device / Node | JSON WebSocket `/dmp-c/v1`, DMP-C version 2, `CHALLENGE`, `AUTH`, `AUTH_OK`; Ed25519 Device signature of pipe-separated node/session/nonces/expiry | Mutual role-bound authentication, ephemeral X25519, directional encrypted records |
| Node / Node | `ws://host:port`; initiator `{id,challenge}`, responder `{id,signature}`; inbound checks NodeID PoW but not initiator possession | Same v3 record layer, independent directional DNSS authorization |
| Mesh wire | `{t:REAL,d:JSON(packet),x:padding}` or DUMMY; `ROUTE_PROBE_V2` carries route/back route, metric, hop limit, global NCRH; DATA carries route and envelope | Hop labels, local NCRH, opaque DeviceCiphertext, bounded batches |
| DNSS | PWA encrypted Device material `dnss/v1/NodeID`, 16 bytes; SQLite registry composite blind DNSS / raw RouteID; gateway pending registration cleared after grant | Stable Device/Node DNSS, runtime registration bound to authenticated Device key; rebuild after Node restart |
| Public authority | Route-signed EntryGrantV1 includes NodeID, route key, generation and lifetime; no session/DNSS signature binding | Session-bound proof plus grant plus activation work |
| Private routes | Account-scoped lifecycle and locator configuration; gateway does not distinguish authority | Root-capability proof, no mandatory public grant or AccountID KDF input |
| Control hole | Inbound register/unregister and Probe lack resource authority checks | Fail closed before any side effect |
| Mailbox | SQLite `offline_mailbox(target_hash,packet_json,notification_id)` indexed by locator blind alias; PULL per handle; ACK deletes | Durable DNSS mailbox, all-row leased drain, delete only after awaited successful send |
| Device events | Public contact ciphertext boundary exists, but outer type is visible; private receive tied to active Account | Encrypted Device envelope and Inbox with independent dispatch |
| PoW | Node identity BLAKE3 prefix; resource activation SHA-256 transcript V2, production 20–24 bits, consumed replay cache | Preserve work policy; independently authorize each Node direction |
| Capabilities | Policy flags route/accept/fallback/signal/be_turn/blob; no working S-TURN service | Canonical S-TURN alias and health-based descriptor |
| Tact | 1.5 seconds; per-packet sends, padding, DUMMY; transient queue drops failed sends | 500ms per-peer bounded batch, no padding/cover, retry retention |
| WebRTC | Core offer/answer/ICE via sendVoipSignal/message transport | Ephemeral signaling WSS plus coturn; Device-encrypted call request |
| Files | Existing message/media path | Encrypted chunks over DataChannel, integrity/cancel/progress/limits |
| Account crypto | S/P/timestamp/shift and bundled Kyber prototype | Loss-tolerant epoch keys with authenticated fresh-entropy updates |
| Installer | Immutable revision pin, systemd/env/nginx/firewall; no CLI password or coturn; selected visibility not used in env output | Idempotent parser, verifier secret file, real password gate and optional coturn |

## Implementation sequence

A. Inventory and repeatable all-suite runner.
B. Shared DMP-C v3 cryptographic record/handshake, Python/JS interoperability,
   then gateway and peer integration with role-separated capabilities.
C. Runtime DNSS ownership and session-bound public/private route authorization.
D. Dedicated durable mailbox database/keys and all-row send/commit drain.
E. Device envelope, encrypted Inbox and account-independent dispatcher.
F. Probe-installed hop labels and local NCRH.
G. Bounded 500ms scheduler, retry and duplicate handling.
H. Password challenge/verifier, fragment import and installer.
I. Capability directory, coturn health and ephemeral signaling.
J. Device-encrypted CallRequestV2 and actual call flow.
K. DataChannel encrypted file chunks and UI integration.
L. Account epoch ratchet and loss/reorder/update tests.
M. Full regression, Chrome acceptance, documentation, push and exact-hash deploy.

Each milestone must pass relevant executable tests before commit. Existing
tests are retained; obsolete expectations require an explicit migration note.
`python tools/test_all.py` runs Node, Origin, and all executable PWA suites and
reports every failure. Use Python 3.12 with the pinned client dependencies and
`httpx==0.27.0` for the current Starlette test client.

## Target invariants (PLANNED until supported by integration tests)

Account identity, ratchet, content and receipts stay in the Account layer.
Device plaintext is `{version,route_id,type,packet_id,device_metadata,account_payload}`;
all fields are encrypted to the destination Device. Type is an extensible
bounded string. Route is for local dispatch, not intermediate forwarding.
Locked Account payloads are persisted encrypted at the Device layer before
being processed after unlock. Device fetch/storage is not Account DELIVERED.

Device DNSS survives socket loss and IP changes; socket authentication rebinds
it. Node restart discards registration/routes, but retains mailbox ciphertext
and durable mailbox alias keys. No BootID. Node directions use distinct DNSS
and independent work. PULL never accepts a caller-selected queue.

Mailbox drain selects all quota-bounded rows under a short lease, sends one
logical result, and deletes only its reservation in a transaction after send
success. Failure releases the lease; crash after send may duplicate delivery.
Client packet-id dedupe is required. Routing and mailbox key lifetimes differ.

Public routes use Route signatures; private routes use pairing contributions
and root capability. Both authorize the specific session/DNSS/generation and
required work. NCRH never authorizes ownership. Each hop replaces a random
local label using encrypted local metadata; Account identifiers never enter
locator derivation or Node descriptors.

Batching aggregates routes sharing a next hop every 500ms, with item/byte and
queue bounds and FIFO within a route. Control frames are immediate. Without
padding and cover traffic this reduces timing granularity but does not prevent
global traffic correlation.

S-TURN means live ephemeral signaling plus TURN relay, with short-lived TURN
credentials. Call request carries expiring session material and a bounded
ringtone inside Device encryption; SDP/ICE uses signaling WSS. File content
uses encrypted/integrity-checked DataChannel chunks. Password proofs bind a
fresh nonce and transcript; no raw password on wire or in browser storage.

Epoch message keys are independently derived from root/direction/epoch/random
message id. Repeated self-contained updates tolerate loss; acknowledged old
roots are erased. Fresh X25519 entropy is required for compromise recovery;
ML-KEM needs exact implementation review before any hybrid/PQ security claim.

TODO: future DHT can carry the same NodeDescriptor serialization; no DHT is
part of this change. No anonymity, formal PCS/PFS, or PQ claim is made from
schema or unit tests alone.

## Baseline verification (before production changes)

Python 3.12.14, Node 24.19.0, pinned requirements: Node 98/98 pass;
Origin 11/11 pass; PWA 23/25 suites pass. Two pre-existing failures:
`historical_webauthn_release.test.js` executes the old release patch against the
new loader with an incomplete DOM fixture; `historical_webauthn_source_regression.test.js`
expects WebAuthn implementation inside `release.js`, now moved to runtime
modules. These failures are retained and must be migrated without weakening
WebAuthn requirements. Baseline test output is local, outside Git.

## B1: shared secure-session implementation

IMPLEMENTED: `secure_session.py` and `secure_session.js`, shared v3
HELLO → signed CHALLENGE → signed AUTH, X25519 ephemeral keys,
HKDF-SHA256, separate send/receive keys, XSalsa20-Poly1305 encrypted records.
Roles DEVICE/NODE, identities, suite, both ephemeral keys, nonces and expiry
are bound into the transcript. The Python async adapter serializes concurrent
sends including sequence allocation; failures destroy the session.

Wire suite: `X25519-HKDF-SHA256-XSALSA20POLY1305`. Canonical JSON uses sorted
ASCII property names, ASCII-escaped strings, safe integers, boolean/null and
arrays/objects, maximum depth 32. Signed hash is SHA256 of
`D-MASH|DMP-C|3|HANDSHAKE\0` plus canonical `[hello,challenge_without_signature]`.
Responder and initiator signatures have distinct domain labels. HKDF salt is
that hash; IKM is `X25519\0 || u32be(32) || shared`; info is the protocol domain
plus suite. First/second 32 bytes are initiator→responder/responder→initiator.
A future hybrid suite must bind its own suite and length-delimited KEM inputs;
this implementation accepts no ML-KEM or silent fallback.

SECURE frames have version 3, integer sequence, standard canonical base64
ciphertext. Secretbox nonce is 16 zero bytes plus u64be(sequence). Directional
keys and fresh connection keys separate nonce domains; sequence is strict,
starts at zero and is bounded to 2^32−1. Maximum plaintext record: 1 MiB.
Malformed, replayed or reflected incoming records close and clear keys.
Python/JavaScript clear mutable key buffers and release references; neither
managed runtime promises forensic erasure of all library/internal copies.

IMPLEMENTED: FastAPI `/dmp-c/v3` DEVICE endpoint with encrypted PING/STATUS;
NODE roles and unimplemented resource operations fail closed.
PARTIAL: v3 is not yet the active PWA or Node↔Node transport. Existing v2 path
remains unchanged pending authority/mailbox migration. This is not completion
of milestone B or the overall refactor.

Validation: 111 Node tests pass (98 baseline + 13 new). New tests include
RFC 5869 vector, real bundled TweetNaCl↔PyNaCl interoperability for both roles,
mutual possession, wrong identity/role/signature/expiry, challenge/auth replay,
record tamper/reflection/replay, fresh reconnect keys, erasure and real ASGI
endpoint tests. PWA baseline still has the two documented historical failures.
Cryptographic references: RFC 5869 (https://www.rfc-editor.org/rfc/rfc5869),
RFC 7748 (https://www.rfc-editor.org/rfc/rfc7748); references do not constitute
an audit of this protocol composition.

## B2: Node↔Node migration

IMPLEMENTED: `network.py` now uses the common v3 handshake and secure socket.
Saved endpoints pin their known NodeID on reconnect; new peers are authenticated
as first-contact identities and must still satisfy the existing Node identity
PoW. Both directions independently generate 128-bit DNSS, mine and verify
resource work bound to recipient NodeID, sender NodeID, DNSS, and the fresh
session transcript. NODE_REGISTER/NODE_AUTHORIZED are encrypted, immediate
control operations. One direction's work never authorizes the reverse.

Node data operations are MESH_PROBE/MESH_DATA; NODE_CONTROL currently supports
keepalive. Device operations including PULL are rejected on Node channels.
Old REAL/DUMMY wrappers exist only at the local adapter boundary and are not
sent as cleartext; padding is not transmitted by the adapter. Tact scheduling
and existing locator-bearing packets still await milestones F/G.

Compatibility: peers must upgrade together; there is no automatic fallback to
the old unauthenticated-initiator handshake. Host:port dialing retains its
existing ws transport; explicit wss URLs retain TLS verification. Encrypted
DMP-C is additional protection, not a substitute for a deployment's TLS/WSS.
Node authorization currently uses a new directional DNSS per connection;
Device DNSS persistence remains a separate unfinished migration.

Validation: 113 Node tests pass, including two real loopback WebSocket peers,
independent directional DNSS/work, data transport, Device-operation rejection,
and refusal when one direction supplies bad work. Identity-prefix mining is
mocked only in these focused integration fixtures; resource proof verification
is real with reduced test-only difficulty. Production difficulty is unchanged.

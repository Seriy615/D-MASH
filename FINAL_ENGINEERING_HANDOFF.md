# FINAL ENGINEERING HANDOFF + PROJECT STATE REPORT + ROADMAP

**Snapshot date:** 2026-08-31  
**Authoritative development checkout:** `/home/jcode/D-MASH` on `crjcvfugaq`  
**Git snapshot:** `main` at `05b10849937cf7cc3e629295d4233befadcfe938`  
**Scope of this report:** evidence from the current tree, reachable Git history, runtime inventory, unit tests, and observed infrastructure acceptance. It deliberately distinguishes code existence from end-to-end proof. No secret values are included.

> **Read this first:** D-MASH is a prototype messenger with a browser PWA, a Python mesh-node prototype, an authenticated DMP-C browser-to-node gateway, opaque-locator routing/storage work, a legacy PHP relay, and an optional Origin notification service. The server development environment is ready. The core product milestone, a real two-browser PWA-to-mesh-to-PWA delivery with no PHP relay, is **not accepted**.

## 1. Executive summary

D-MASH has evolved from an early Python/PHP/PWA prototype into a partially integrated architecture with a distinct client gateway and an opaque-routing transport layer. Its code contains a credible direction for `PWA -> Entry Node -> Python peer mesh -> destination Entry Node -> PWA`, but the complete public/browser path remains unproven. Existing Node connections and DMP-C authentication must not be interpreted as proof of message transport.

Major completed phases include legacy PWA/relay functionality, Python node networking and signed peer handshakes, a PWA node-selection UI, DMP-C authentication, blind locator persistence, mailbox/PULL/ACK APIs, Origin notification isolation, update-cache work, and server/Jcode migration. The primary next engineering milestone is **M1: a real, instrumented, no-relay transport vertical slice between two browser clients and at least two Python nodes**.

| Area | Status | Evidence-based meaning |
|---|---|---|
| PWA | PARTIAL | Usable browser shell, QR/pairing code, node UI, DMP-C client code and legacy UI exist. |
| Node | IMPLEMENTED | Python FastAPI node, identity, SQLite state, P2P listener, DMP-C WebSocket gateway exist. |
| Origin | IMPLEMENTED/PARTIAL | Isolated notification service and personal-bot lifecycle code/tests exist. Not a transport authority. |
| Routing | PARTIAL | Legacy routing exists; opaque DMP-C probe/route-alias layer exists with unit tests. Real multi-node convergence is unproven. |
| Transport | PARTIAL | DMP-C `SUBMIT/PULL/ACK` and PWA calls exist. Browser-to-browser no-relay acceptance is missing. |
| T-Ratchet | PROTOTYPE | Time-epoch ECDH-derived scheme is implemented. It is not a reviewed modern double-ratchet/T-Ratchet v2. |
| Crypto | PARTIAL/PROTOTYPE | Real libraries/primitives are used, but composition and key lifecycle are not security-audited. |
| Store-and-forward | PARTIAL | Node mailbox, live-session push, PULL and ACK code/unit tests exist. End-to-end offline acceptance is missing. |
| Notifications | PARTIAL | Opaque delayed Origin trigger and personal-bot vault/enrollment tests exist. Product integration is incomplete. |
| DSP overlay | PROTOTYPE | Python audio/PCP utilities and PWA call UI artifacts exist; no accepted PWA overlay path. |
| Deployment | IMPLEMENTED/PARTIAL | Services run on ems-vps; source and runtime trees are distinct and deployment lineage needs discipline. |
| Testing | PARTIAL | Focused Python unit tests and provider/infrastructure smoke tests exist. No real browser mesh acceptance. |
| Documentation | PARTIAL | Current authoritative documentation is README plus this handoff. Earlier Markdown context was intentionally purged from reachable Git history. |
| Infrastructure/Jcode | IMPLEMENTED | Isolated user, canonical repo, Nodule providers, one persistent tmux Jcode session, and GitHub access are verified. |

## 2. Project evolution

### Phase A: early Python/socket prototype, 2024 to early 2026
**Starting architecture:** uploaded Python `main.py`, socket experiments and early PWA iterations.  
**Implemented remnants:** `D-MASH/client/backend/{core,network,crypto,database}.py`, legacy PHP endpoints, and PWA core.  
**Important evolution:** early files were repeatedly uploaded, removed and re-added. Git history before 2026-08 has sparse commit descriptions, so exact intent is partly **UNKNOWN**. `f3af555` labels a Beta-3/T-Ratcher stage; `17d099d` changed node handshake; `e78f752` changed crypto.

### Phase B: Beta PWA, legacy relay, and epoch crypto
**Architecture:** PWA encrypted/verified envelopes and sent them to `D-MASH PWA/api/pidorskiy_api.php`; PHP acted as compatibility relay/storage and also contained Telegram-era behavior. Python node routing existed separately.  
**Problem discovered later:** PWA node connection was not necessarily the message path. A delivery UI could therefore be misleading if relay was used.  
**What survives:** legacy relay code and explicit legacy transport mode remain. The PHP relay is not the target mesh design.

### Phase C: M0 baseline and Origin isolation, 2026-08-25
Commit `07bf8e3` established a baseline. Commits `615aeb9` through `354b659` added/authored:
- an authenticated PWA node gateway foundation;
- isolated Origin notification HTTP service;
- encrypted personal-bot token vault, one-time enrollment and signed webhook flow;
- replay nonce persistence and unit tests;
- PWA personal-bot settings.

**What was corrected:** Origin notification is a side channel, not a mandatory message relay or routing identity system.

### Phase D: PWA UX/node selection/release handling
Commits `fffaf77` through `7e2c2be` fixed runtime exposure of `NodeManager`, service-worker activation/cache behavior, visible node selection, i18n/app shell, rollback behavior and manual node selection. `nodes.json` contains test endpoints.  
**Current value:** PWA can select/connect to a node and uses authenticated WebSocket control traffic. This is not transport acceptance.

### Phase E: opaque mesh bridge and routing iteration
Commits `769725b`, `31a7cc0`, `bbc3f4e`, `15b500a`, `5b125ff`, `36b2239`, `d34edcc`, `4ce0c99`, `109ff56` added/changed:
- blind aliases for local inbound locators and route records;
- authenticated DMP-C operations;
- PWA route persistence and QR-driven locator setup;
- probe processing and shortest-hop replacement logic;
- mailbox/live-session destination notifications;
- cleanup of route state when deleting a peer;
- reconnect/route restoration fixes.

**What remains partial:** it is a bridge around existing Python peer networking, not proof of a completed Tentacle-style routing protocol. Current packet fields still use names `route_id` and `back_route_id`; storage aliases are blind, but in-flight fields are raw opaque values.

### Phase F: deployment and infrastructure migration
The project was moved to ems-vps with production/stage runtimes, a Python node service, Origin service and Nginx/PHP-FPM. The canonical development checkout became `/home/jcode/D-MASH` under an unprivileged user. Jcode/Nodule/tmux/GitHub were accepted separately. See sections 15 and 16.

## 3. Work completed

### A. PWA / frontend
**STATUS: PARTIAL.** Files: `D-MASH PWA/not_messenger/{index.html,js/core_engine.js,js/node_manager.js,js/app_shell.js,js/storage.js,sw.js}`.  
**Changed:** calculator-disguised PWA shell, responsive UI/i18n, QR handling, contact/chat UI, node selection, release discovery and service-worker activation. `NodeManager` implements a DMP-C WebSocket client.  
**Behavior:** mesh is the default mode; legacy relay is explicit. `Core.sendMessage` attempts route restore, probe, encrypt/sign, then `submitEnvelope` in mesh mode. `syncNetwork` performs PULL, verifies candidate sender signature, decrypts client-side, saves local history, then ACKs.  
**Limitations:** no browser acceptance proving this path across nodes. PWA stores route configuration in `sessionStorage`; reload/reconnect behavior has had repeated fixes. Calls/voice UI exists but is not accepted.

### B. Client storage/state
**STATUS: PARTIAL.** Files: `storage.js`, `core_engine.js`.  
**Changed:** IndexedDB boxes, aliases, local message history and pairing/route data. Pairing contribution is described in code as locally vaulted.  
**Limitations:** actual persistence migration, cleanup and cross-browser behavior need browser tests. A historical IndexedDB `TransactionInactiveError` was observed during development; fixes were committed but full acceptance is absent.

### C. E2EE / cryptography
**STATUS: PROTOTYPE/PARTIAL.** Files: PWA `core_engine.js`, Python `crypto.py`.  
**Changed:** PWA uses Argon2id, TweetNaCl Ed25519 signatures, Curve25519 box operations, secretbox, and bundled Kyber-768 WASM. Python uses PyNaCl, BLAKE3, Argon2id, Ed25519/Curve25519, SecretBox and SealedBox.  
**Current behavior:** PWA envelope code signs ciphertext and verifies signatures before decrypting on receive. Python NodeCryptoManager uses an Ed25519 node identity and RAM-only BLAKE3 keyed blind salt.  
**Limitations:** see section 6. This is not a completed cryptographic audit or production-security claim.

### D. T-Ratchet
**STATUS: PROTOTYPE.** Files: PWA `core_engine.js`; Python `crypto.py`.  
**Changed:** epoch/offset based key derivation and handshake packet types exist. PWA comments call its multilayer mechanism T-Ratchet/Kyber/signatures. Python derives an ECDH shared secret then BLAKE3 key by five-minute epoch, trying offsets `[0,-1,+1]` while decrypting.  
**Limitations:** no per-message chain ratchet, no reviewed skipped-message mechanism, no demonstrated PCS, and no v2 implementation. Do not call it a formal Double Ratchet.

### E. Node
**STATUS: IMPLEMENTED/PARTIAL.** Files: `D-MASH/client/backend/{main.py,core.py,database.py,network.py,crypto.py}`.  
**Changed:** FastAPI lifecycle creates node identity, SQLite system database, P2P listener, TACT engine, peer maintainer and optional notification trigger.  
**Limitations:** permissive CORS, runtime configuration scattered through environment/systemd, and no accepted multi-node production topology test.

### F. Node-to-node networking
**STATUS: IMPLEMENTED/PARTIAL.** File: `network.py`.  
**Changed:** WebSocket P2P server/outbound dial; Ed25519 challenge signature check; NodeID PoW-prefix validation; active connection table; encrypted neighbor/outbox DB records; known-neighbor reconnect loop.  
**Limitations:** no DHT, no formal peer budget/topology policy, duplicate-connection behavior not independently tested, and `connect_to` logs peer prefixes. PoW remains implemented despite later architecture discussions to defer blockchain-like mechanisms.

### G. Routing / PROBE
**STATUS: PARTIAL.** Files: `transport.py`, `database.py`, `network.py`; tests `test_blind_route_storage.py`, `test_transport.py`.  
**Changed:** DMP-C probe packets, local inbound locator registration, blind route aliases, TTL field, hop counting, shorter-route replacement and health tie handling.  
**Current behavior:** `receive_probe` computes `candidate_hops = hops + 1`; `add_route_alias` keeps lower hop candidate and can tie-break by health. Node dispatch forwards a DMP-C probe only when local best candidate changed.  
**Limitations:** no real graph test with actual Python processes proving a later shorter route wins in the network. Probe expiry/recovery/dedup quality is incomplete.

### H. Mailbox / store-and-forward
**STATUS: PARTIAL.** Files: `transport.py`, `database.py`, `notification.py`.  
**Changed:** `offline_mailbox`, destination-local storage after stripping route fields, live DMP-C session delivery, PULL retaining packets, ACK deleting matching packet, and notification scheduling/cancellation.  
**Limitations:** unit tests cover behavior, but offline browser disconnect/reconnect/PULL/ACK acceptance is missing.

### I. Origin
**STATUS: IMPLEMENTED/PARTIAL.** Files: `origin/{notification_service.py,personal_bot_enrollment.py,personal_bot_vault.py}` and tests.  
**Changed:** signed opaque notification boundary, one-time enrollment, encrypted bot token vault, lifecycle controls.  
**Must not do:** route user traffic, decrypt messages, or replace route locators.  
**Limitations:** current product dependency and runtime wiring need integration acceptance.

### J. Notifications
**STATUS: PARTIAL.** Node `NotificationTrigger` delays opaque notification for pending mailbox material; Origin verifies node signature and deduplicates.  
**Evidence:** unit tests assert payload excludes sender/message and cancellation after pickup.  
**Limitations:** actual provider delivery/retry/availability is not an end-to-end acceptance result.

### K. DSP overlay
**STATUS: PROTOTYPE.** File `dsp.py` supplies WAV/PCM conversion, scrambling and PCP audio encode/decode. PWA has WebRTC/call UI fragments.  
**Limitations:** no accepted browser integration or transport substrate proof. Do not expand before messaging transport.

### L. PhantomCall / GhostVoice
**STATUS: UNKNOWN/PROTOTYPE.** PWA contains call overlay, ICE/answer/hangup and proximity UI names. No authoritative design document remains and no complete accepted call path was found. Treat as frozen prototype UI/code until reviewed.

### M. Deployment
**STATUS: IMPLEMENTED/PARTIAL.** Systemd services active: `dmash-node`, `dmash-messenger`, `dmash-messenger-stage`, `dmash-origin-notify`; Nginx and PHP-FPM active. Test P2P listener is public on `19090`; HTTP services are loopback behind proxy.  
**Limitation:** source checkout `/srv/dmash-source/D-MASH` and runtime copies `/opt/dmash-node`, `/srv/messenger*` are distinct. A disciplined promotion procedure is required.

### N. Tests
**STATUS: PARTIAL.** Focused Python unit suites cover blind storage, DMP-C signature function, transport/mailer behavior, Origin service, enrollment and vault. A `stress_test.py` and Docker compose topology exist.  
**Limitation:** unit tests are not browser or live multi-node acceptance.

### O. Observability/debugging
**STATUS: PARTIAL.** Logs and transport states exist (`SUBMITTED_TO_ENTRY`, `ROUTE_NOT_ARMED`, destination states); release IDs exist.  
**Limitations:** production logging/privacy policy is not fully enforced, correlation discipline is incomplete, and historical UI displayed optimistic states during failed transport work.

### P. Security/privacy hardening
**STATUS: PARTIAL.** Blind node-local aliases, encrypted route blobs, DMP-C client signature challenge, Origin signature verification, secret-file permissions, explicit legacy mode and no automatic relay fallback were added.  
**Limitations:** current Node process must retain the RAM blind salt to resolve aliases, peer and packet metadata exist in memory/in-flight, and no independent security review was performed.

### Q. Documentation/context
**STATUS: PARTIAL.** README was restored; this handoff is the authoritative broad context. Earlier decision/protocol/roadmap Markdown files were deliberately removed from current tree and reachable Git history during repository cleanup. Their exact contents are therefore unavailable from current Git.

### R. Developer infrastructure/Jcode
**STATUS: IMPLEMENTED.** See sections 15 and 16.

## 4. Architecture: current authoritative state

### PWA
**Responsibilities:** generate/store client keys, perform pairing and envelope crypto, authenticate to entry Node using Ed25519 over DMP-C challenge, hold opaque locator route config, encrypt/sign payload, PULL/verify/decrypt/render/ACK.  
**Must not:** treat node connection as delivery, silently use PHP relay in mesh mode, put recipient public user ID in mesh packet metadata, or delegate decryption to node.  
**Trust boundary:** browser local storage and user-controlled code execution.  
**Persistence:** IndexedDB/local/session storage including contact/alias/route state.  
**Interface:** WSS DMP-C `/dmp-c/v1`; legacy relative PHP endpoint only when explicit legacy mode is selected.

### Entry/intermediate Node
**Responsibilities:** authenticate PWA control session, blind locators for persistence, route/forward opaque packets, maintain P2P peers, store destination mailbox ciphertext, deliver to live local DMP-C sessions, trigger opaque notification delay.  
**Must not:** decrypt PWA E2EE payload, require recipient user ID in DMP-C packet, persist raw locator as a DB value, or become a user-message relay by identity.  
**Trust boundary:** node operator sees transport timing, peer addresses and in-flight opaque route identifiers.  
**Persistence:** SQLite peer directory, blind routes, local bindings, outbox, seen packets, offline mailbox. Route/binding index values are blind aliases and blobs are encrypted to node identity.

### Origin
**Responsibilities:** notification side-channel, bot enrollment/token vault/lifecycle.  
**Must not:** route mesh packets, hold E2EE plaintext, serve as primary message transport.  
**Trust boundary:** receives a signed opaque notification request, may know opaque owner/binding and notification delivery target depending on feature.  
**Persistence:** Origin-specific state/vault, separate from Node mailbox.

### Target data flow, intended versus evidence

```text
Control plane
PWA --DMP-C AUTH/REGISTER/PROBE/PULL/ACK--> Entry Node

Data plane (implemented code path, not accepted end-to-end)
PWA A --ciphertext envelope + sender proof--> Entry Node A
Entry A --DMP_C_DATA(route_id, envelope)--> P2P peers
intermediate Node(s) --best blind route next hop--> Entry Node B
Entry B --live DMP-C delivery or offline_mailbox--> PWA B
PWA B --verify sender proof, decrypt--> local history/UI --ACK--> Entry Node B

Notification path
Destination mailbox pending > delay -> opaque signed Node request -> Origin -> optional provider
```

**Encryption:** E2EE ciphertext is produced/checked in PWA. DMP-C PWA control auth uses signature over challenge transcript.  
**Routing metadata:** in-flight packet has `route_id` / `back_route_id` opaque strings, hops/ttl/id; persistent node DB uses keyed blind aliases.  
**Mailbox:** destination strips route fields before storing `packet_json`; packet ciphertext remains.  
**ACK:** authenticated DMP-C client ACKs delivery ID; Node removes matching mailbox packet restricted to registered locator handles.

## 5. Legacy versus current architecture

| Legacy component | Why it existed | Current replacement | Still reachable? | Removal prerequisites |
|---|---|---|---|---|
| `pidorskiy_api.php` | PHP relay/storage, legacy message/PULL path | DMP-C + `NodeTransportService` + P2P mesh + mailbox | Yes, explicit `transportMode === legacy`; PWA fetch sites remain | Real browser no-relay acceptance, migration/rollback plan, proof legacy users are retired |
| `tg_webhook.php` / PHP Telegram logic | Legacy notification/control integration | Origin notification service and personal-bot vault | Runtime-dependent, PHP remains deployed | Origin feature acceptance and migration review |
| Python legacy `PROBE`/`DATA` handlers | Pre-opaque routing baseline | `DMP_C_PROBE` / `DMP_C_DATA` transport adapter | Yes, both handlers exist in `network.py` | Full opaque route protocol acceptance and compatibility removal plan |
| User-ID/route derivation helpers in Python `CryptoManager` | Earlier routing identity model | Pairing-derived opaque locators in PWA/transport direction | Code remains | Audit all old call paths and replace only after transport tests |

**Silent fallback:** current `Core.sendMessage` mesh branch returns an error/warning when route is missing; it does not call PHP. For forced handshake it offers an explicit user confirmation to switch to legacy. This is the intended behavior and should be regression-tested.  
**Caveat:** legacy mode can still call PHP at `ui_logic.js:78`, `core_engine.js:668,815,910`; production PHP runtime remains deployed. Therefore PHP is not removed and mesh acceptance must instrument/block it.

## 6. Cryptography and T-Ratchet state

### Current implementation
- **PWA:** Argon2id-derived local material; Ed25519 signing; Curve25519 box; XSalsa20-Poly1305 `secretbox`; Kyber-768 WASM key/capsule functions; ciphertext sender proof.
- **Python client prototype:** PyNaCl Argon2id; Ed25519 identity/signatures; Curve25519 ECDH; SecretBox; BLAKE3/SHA-256 based derivations.
- **Node:** Ed25519 NodeID, challenge signatures, BLAKE3 keyed blind hash with RAM-only random key, SealedBox metadata encryption.
- **Origin:** PyNaCl signature verification and encrypted token vault behavior are unit-tested.

### Important limitations and unresolved questions
- The Python `CryptoManager.get_route_id(A,B)` is deterministic from public keys. This conflicts with the later pairing-secret locator requirement. Treat it as legacy/unsafe for new routing.
- Kyber-768 WASM artifacts and PWA calls are present, but no complete Python ML-KEM dependency/protocol interoperability or accepted hybrid test was found. Presence of the bundled PWA artifact is not a production PQ claim.
- Epoch-based ECDH key derivation is not a full ratchet. It relies on a long-lived static ECDH secret plus time epoch, uses a small time window, and lacks independently validated replay/skip/PCS semantics.
- PWA’s hybrid Kyber/ECDH handshake and packet formats exist but have no formal protocol specification, test vectors, downgrade analysis, interoperability test, or external review.
- Domain separation is inconsistent across legacy helpers. Example comments and code use different BLAKE3/SHA-256 paths. A future protocol review must inventory every wire format before crypto change.
- Password-derived identity uses a deterministic username-derived salt in Python legacy code. This should not be presented as modern account/identity provisioning.
- The node blind salt is randomly generated only in RAM. After node restart, previously persisted blind aliases cannot be recomputed from raw locators by the new process, so durable route/binding lookup continuity is a known functional trade-off that requires explicit recovery/re-arming behavior.
- Key persistence, backup/recovery, device migration and compromise recovery are **UNKNOWN/NEEDS VERIFICATION** at product level.
- Do not redesign crypto during M1 transport work. First stabilize and observe transport using existing envelopes.

### T-Ratchet v2
**DESIGNED/PLANNED, not implementation.** Any future v2 must have a reviewed protocol specification, domain-separated KDFs, per-message chains, replay/skipped-key policy, explicit identity binding, PQ transition policy and test vectors before replacement.

## 7. Routing and PROBE state

**Implemented:**
- PWA stores directional route locators per peer and registers its inbound/back locator at entry Node.
- `START_PROBE` carries `route_id`, `back_route_id`, `hops`, `ttl`, packet id.
- Node blinds raw locators before persistent indexing.
- `receive_probe` learns reverse path with `candidate_hops = hops + 1`; destination can mark route local.
- `DatabaseManager.add_route_alias` stores `{next_hop_id,hops,is_local,health,generation}` encrypted in a route blob and prefers fewer hops, then health on tie.
- DMP-C data lookup uses blind route alias; destination stores/delivers, intermediate forwards.

**Evidence:** `test_blind_route_storage` asserts raw locator absent from binding/routing blob; `test_transport` asserts long then shorter destination probe picks hop 3/local and transport packet excludes `recipient`, `recipient_id`, `plaintext`.

**Not proven:** actual peer graph propagation, TTL enforcement behavior, probe dedup robustness, route expiration/recovery, health measurement, loop resistance, and a real later-arriving short route in separate node processes. A unit test is not a mesh graph acceptance test.

## 8. Node network and peering

**Implemented now:** NodeID is Ed25519 verify key hex; NodeID generation searches a BLAKE3 PoW prefix. P2P WebSocket outbound/inbound handshake exchanges challenge and node signature, verifies NodeID PoW and signature, tracks active connections and saves neighbor address. A ten-second `maintain_mesh_peers` loop redials known dialable peers. Pings use WebSocket configuration.

**Designed/future:** robust bootstrap policy, peer hints/budget, topology management, duplicate connection arbitration, reputation/health protocol, DHT/decentralized discovery. **No DHT exists.**

**Risk:** PoW is implemented in legacy node identity despite a later desire to avoid blockchain-like scope. Do not expand it without an explicit threat-model decision.

## 9. Privacy and threat model

| Party | Knows/observes | Must not know | Persists | Compromise impact |
|---|---|---|---|---|
| PWA | local identities, pairing state, plaintext | other users’ secrets | browser state/history | plaintext/local keys at risk |
| Entry Node | client connection timing, in-flight opaque locator, chosen peer | message plaintext, mandatory recipient user ID | blind aliases/routes/mailbox ciphertext | local metadata/timing and ciphertext exposure |
| Intermediate Node | neighbor/next-hop, opaque packet route field, timing/size | PWA plaintext and recipient identity by user ID | outbox/seen/peer state | topology/timing observation |
| Destination Node | local inbound alias, mailbox ciphertext, live-session availability | plaintext | mailbox and blind binding | offline ciphertext and timing exposure |
| Origin | signed opaque notification identity/binding and provider target as configured | message plaintext, mesh route locator as identity | enrollment/vault/dedupe state | notification metadata/provider target |
| Bootstrap infrastructure | endpoint/connection metadata | plaintext/route pairing secret | deployment logs/config | traffic correlation |
| Notification provider | notification request destination and timing | message plaintext unless implementation sends it, which current Node test forbids | provider-side metadata | external metadata disclosure |

**Known metadata leaks:** IP/address at peer and PWA boundary; timing, packet size, active session status, topology, connection retries, node logs, Origin notification timing. Blind storage protects persistent raw locators only while RAM blind key remains secret; it does not hide in-flight locator value from a Node handling it. The current peer P2P WebSocket channel authenticates handshake identity but does not provide a demonstrated encrypted transport layer, increasing passive network-observer exposure.

## 10. Testing and evidence

| Capability | Test/evidence | Result | Confidence |
|---|---|---|---|
| DMP-C invalid signature | `test_client_gateway.py`; public WSS invalid auth was previously observed closing | PASS | medium |
| Blind persistent storage | `test_blind_route_storage.py`, `test_transport.py` | PASS unit | medium |
| Shortest route replacement | transport/database unit tests long then short | PASS unit | medium |
| No recipient/plaintext in DMP-C DATA | `test_transport.py` assertions | PASS unit | medium |
| Mailbox retained until ACK | `test_transport.py` | PASS unit | medium |
| Destination live session callback | `test_transport.py` | PASS unit | medium |
| Locator deletion cleanup | `test_transport.py` | PASS unit | medium |
| Opaque notification payload/dedupe | `test_notification.py`, Origin tests | PASS unit | medium |
| Origin bot vault/enrollment | Origin unit tests | PASS unit | medium |
| Node unavailable/no silent PHP fallback | code inspection only | PARTIAL | low |
| Direct two-node PWA transport | not completed | FAIL/UNVERIFIED | none |
| Multi-hop transport | not completed | FAIL/UNVERIFIED | none |
| Browser A->B and B->A | not completed | FAIL/UNVERIFIED | none |
| Relay absence in browser flow | not completed | FAIL/UNVERIFIED | none |
| Offline reconnect PULL/ACK in browsers | not completed | FAIL/UNVERIFIED | none |
| Intermediate plaintext absence | packet/unit evidence only | PARTIAL | low-medium |
| Full client suite | prior local run blocked by missing PyNaCl in that environment | BLOCKED | low |
| Server Jcode providers | Nodule OpenAI/Anthropic/Grok and native Gemini smoke | PASS | high for dev infra only |

## 11. Known bugs and technical debt

| Priority | Issue/evidence | Impact | Recommended action |
|---|---|---|---|
| P0 | No real no-relay browser vertical slice | Core product claim unproven | Build M1 acceptance harness before features |
| P0 | Legacy PHP relay remains reachable in explicit mode and runtime | False mesh conclusions possible | Instrument/block relay for M1 tests; retain until migration evidence |
| P1 | Current cryptographic composition not independently reviewed | Security claims unsafe | Freeze crypto; audit/spec/test vectors before v2 |
| P1 | Mixed legacy and DMP-C routing handlers in `network.py` | Ambiguous path/maintenance risk | Trace packet types and isolate compatibility adapter after M1 |
| P1 | Current native Gemini command depends on session environment | Dev workflow fragile if launcher bypassed | Keep launcher canonical; document required environment, do not alter provider config casually |
| P1 | Runtime source trees differ from canonical checkout | Deployment drift | Establish reviewed promotion process and provenance checks |
| P2 | PWA route config in session storage | Reload/device persistence caveats | Test intended persistence model explicitly |
| P2 | PWA/IDB historical transaction race | Handshake/message cleanup reliability | Reproduce in browser and add regression test |
| P2 | `CORS allow_origins=*` in Node | Broad browser exposure | Scope after transport acceptance/threat review |
| P2 | Node log statements include peer prefixes | Metadata/log hygiene | Define production log policy |
| P2 | Docker compose topology exists but not current production runtime | Confusing test/deploy path | Use only as controlled test fixture |
| P3 | Call/DSP artifacts incomplete | Scope distraction | Freeze pending message transport |
| P3 | `setup_nodule.sh` is untracked and contains config-writing logic | Unreviewed working-tree divergence | Decide separately whether to track, ignore, or move outside repo |

## 12. Abandoned or deferred ideas

| Idea | Status and decision |
|---|---|
| Origin as permanent message relay | DEFERRED/REJECTED. Origin is notification side channel, not message transport. |
| Recipient-ID mesh routing | REJECTED for target design. Current new bridge uses opaque locators, though legacy helpers remain. |
| DHT/decentralized discovery | PLANNED later. No DHT implemented. |
| Mandatory full mesh peering | DEFERRED. Current node uses known-neighbor reconnect, not a full topology protocol. |
| Blockchain-like expansion/PoW | DEFERRED. NodeID PoW prefix exists, but do not expand scope without threat-model decision. |
| Mandatory Docker runtime | REJECTED as mandatory production requirement. Docker compose is a test artifact; systemd runs production. |
| Server-side user crypto | REJECTED by current transport boundary. Node routes/stores ciphertext and does not decrypt PWA envelopes. |
| T-Ratchet/ML-KEM-per-message rewrite | DEFERRED until stable transport and protocol review. |
| UI redesign/product polish | FROZEN until transport vertical slice. |

## 13. Current product vertical slice

| Step | Implemented | Tested | Real status/blocker |
|---|---|---|---|
| Offline/QR pairing | PARTIAL | manual code history only | QR import/automatic route setup exists; pairing security protocol not reviewed |
| Directional opaque locators | PARTIAL | unit/code | PWA stores route locators; target derivation depends on pairing contribution, verify protocol later |
| Entry nodes armed | IMPLEMENTED | DMP-C/unit | requires connected PWA/node and successful registration |
| Mutual PROBE | PARTIAL | unit/code | actual two-PWA concurrent probe not accepted |
| Shortest-hop route | PARTIAL | unit | no live multi-node graph proof |
| Ciphertext DATA | IMPLEMENTED code | unit | no accepted PWA A->B mesh proof |
| Destination mailbox/live session | PARTIAL | unit | no browser offline/live proof |
| Destination PWA decrypt | IMPLEMENTED code | no end-to-end | requires valid pairing/key state and delivery |
| ACK | IMPLEMENTED code/unit | no end-to-end | PULL client calls ACK after verify/decrypt |

**Where it breaks operationally:** acceptance evidence stops before real two-browser, two-node encrypted delivery. The next task must prove the entire chain while relay endpoint use is blocked or observed absent.

## 14. What is currently frozen

Until M1 is accepted, do **not** expand: UI redesign, call/DSP features, T-Ratchet v2, ML-KEM-per-message changes, DHT, PoW evolution, native wrappers, notification product polish, Telegram redesign, or broad topology work. These create parallel uncertainty while the central transport substrate is still unverified.

## 15. Infrastructure migration

- **Server:** `crjcvfugaq` / ems-vps.
- **Development user:** `jcode`, UID 1000, `/bin/bash`, no sudo membership.
- **Canonical repo:** `/home/jcode/D-MASH`, owner `jcode:jcode`; `.git` mode 700.
- **Git:** `main`, HEAD `05b1084`; local author `Generalov S.S. <af.svu@mail.ru>`; origin SSH authenticated as repository owner; `ls-remote`, `fetch`, and `push --dry-run` passed.
- **Jcode:** `/home/jcode/.local/bin/jcode`, v0.81.4; config `~/.jcode` mode 700.
- **tmux:** canonical session `dmash-jcode`, launcher `~/D-MASH/dmash-jcode.sh`. It starts/attaches one session, loads dedicated Gemini environment, does not source product `.env`, and guards against creating another session. Observed persistent pane PID `113640` across a fresh SSH reconnect; repeated launcher call kept one session/PID.
- **Runtime services:** active `dmash-node`, `dmash-messenger`, `dmash-messenger-stage`, `dmash-origin-notify`, Nginx and PHP-FPM.
- **Secrets:** existing runtime secret file is root-owned mode 600; Mac `.env` was not copied. Jcode provider env files are mode 600. No secret values belong in Git or this document.
- **Caveat:** `setup_nodule.sh` is an untracked user-owned file in canonical workspace and was not changed/committed.

## 16. Jcode / model infrastructure

| Profile | Endpoint style | Verified models/use |
|---|---|---|
| `nodule-openai` | OpenAI-compatible Nodule | `gpt-5.6-terra` smoke PASS. Intended: Sol architecture/complex reasoning, Terra implementation, Luna memory/context, optional 5.5. |
| `nodule-anthropic` | Anthropic-compatible Nodule | `claude-sonnet-5` smoke PASS. Intended: review/implementation review; Opus 5 security/judge. |
| `nodule-grok` | OpenAI-compatible Nodule | `grok-4.6` smoke PASS. |
| `gemini` | native Nodule Gemini environment | `gemini-3.7-flash` smoke returned `GEMINI_OK` from existing canonical tmux environment. Requires `GEMINI_API_KEY`, Nodule endpoint and API version loaded by launcher. |

No OAuth is required or desired for this server scheme. Do not run provider login or replace profiles unless a smoke test demonstrates failure. For large repository analysis Gemini is a planned useful role, not a substitute for acceptance tests.

## 17. Context / documentation state

| Artifact | State |
|---|---|
| `README.md` | CURRENT BUT SECONDARY. Honest high-level overview and mesh caveat. |
| `FINAL_ENGINEERING_HANDOFF.md` | AUTHORITATIVE handoff snapshot, uncommitted by explicit request. |
| `setup_nodule.sh` | CURRENT LOCAL/UNTRACKED. Contains setup mechanics and must be reviewed before tracking. |
| `.jcode/*` | User-private runtime config, not project documentation. |
| `AGENTS.md`, project `.jcode/`, project skills | Not present in current tree. |
| Earlier architecture/security/protocol/roadmap Markdown | HISTORICAL/UNAVAILABLE from reachable Git due intentional repository cleanup. Do not infer exact text. |

Potential contradiction: code comments and older legacy APIs may claim capabilities beyond current README. Current code/runtime/tests outrank comments; browser acceptance outranks all unit/code inspection.

## 18. Significant change manifest

| Component | Change | Reason/status | Key commits |
|---|---|---|---|
| PWA node UI | Node selection/runtime exposure/service worker release work | IMPLEMENTED/PARTIAL | `fffaf77`, `b6132b4`, `32d8dd2`, `df2ba7c` |
| DMP-C gateway | Authenticated WebSocket operations | IMPLEMENTED | `615aeb9`, `31a7cc0` |
| Opaque transport | Locators, route aliases, PULL/ACK/mailbox | PARTIAL | `769725b`, `5b125ff`, `4ce0c99` |
| Probe shortest path | candidate replacement/gradient test | PARTIAL | `bbc3f4e`, `d34edcc` |
| Explicit relay behavior | no silent fallback in mesh | IMPLEMENTED code | `509e69d`, `5fe2cb9` |
| Pairing automation | QR locator setup/idempotence | PARTIAL | `36b2239`, `9f6996e`, `109ff56` |
| Origin notification | isolated signed notification and bot vault | IMPLEMENTED/PARTIAL | `fbfe85b` to `04d0feb` |
| Node resilience | peer reconnect/outbox priority | PARTIAL | `bb15c43`, `3adc3ba` |
| Infrastructure | ems-vps source/deployment config and README | IMPLEMENTED | `3d1d558`, `05b1084` |

## 19. Current state snapshot

- Branch/HEAD: `main` / `05b10849937cf7cc3e629295d4233befadcfe938`.
- Git tracked worktree: clean. Untracked: `setup_nodule.sh` and, after this requested operation, this handoff file.
- Canonical Jcode session: `dmash-jcode`, one session, persistent runtime observed.
- Node endpoints in PWA `nodes.json`: EMS staging and forge test WSS endpoints.
- Services: active as listed in section 15.
- GitHub connectivity: SSH auth, remote read/fetch, and write authorization dry-run passed.

## 20. Roadmap

### M0: server development environment
**Goal:** frozen/accepted. **Do not change:** provider configuration, runtime secrets, canonical tmux semantics casually. Maintain only when a concrete failure occurs.

### M1: real mesh transport vertical slice
**Why now:** it is the missing product proof.  
**Scope:** two real PWA sessions, two distinct Python nodes, DMP-C auth, QR pairing/locators, probe, ciphertext submission, local delivery/PULL, client decrypt, ACK. Block/instrument PHP relay.  
**Likely components:** PWA NodeManager/Core, `client_gateway.py`, `transport.py`, `network.py`, test deployment scripts.  
**Acceptance:** A->B and B->A PASS, relay request count zero, Node disconnect shows failure not delivered, ciphertext only at intermediate.  
**Must not change:** T-Ratchet design, DHT, UI redesign.

### M2: routing correctness and recovery
Real test graph with a longer early route and later shorter path; expiry, dedup, TTL, loops, health/tie policy, peer reconnection. Acceptance requires observed gradient forwarding.

### M3: store-and-forward reliability
Browser-offline destination, mailbox retention, reconnect PULL, exactly-once-ish client handling/ACK, notification delay/cancel. Add failure/retry observability without social graph logging.

### M4: transport security/privacy hardening
Adversarial DMP-C auth, replay, malformed packets, route alias persistence scans, metadata/log review, packet-size/timing considerations, secret/key lifecycle review.

### M5: crypto/T-Ratchet v2 protocol work
Only after M1-M4. Write reviewed specification and test vectors before changing envelope/key behavior.

### M6: multi-node resilience
Peer budget, bootstrap loss, reconnect/backoff, duplicate connection behavior, topology churn and operational monitoring.

### M7: decentralized discovery/DHT
Only after stable routing semantics and threat model. No implementation exists now.

### M8: DSP PWA integration
Only after reliable encrypted messaging transport. Define actual audio protocol and acceptance tests.

### M9: Origin independence/update hardening
Signed distribution/update process, service-worker lifecycle, origin failover boundaries. Origin must stay out of data routing.

### M10: UX/product stabilization
Real delivery states, pairing UX, explicit compatibility messaging, accessibility/performance after network truth exists.

### M11: security audit/release readiness
Independent crypto/protocol review, deployment review, penetration/adversarial testing, reproducible release evidence.

## 21. Next 10 concrete tasks

| # | Task | Expected output/test | Done when |
|---:|---|---|---|
| 1 | Freeze and record M1 test topology | Two-node/two-browser test plan and relay block switch | Inputs/endpoints/roles reproducible |
| 2 | Install missing test dependencies in isolated test environment | Full current Python unit suite result | Suite runs without environment import block |
| 3 | Add M1 relay instrumentation | Per-client PHP request counter/log-free test signal | Mesh acceptance fails if relay invoked |
| 4 | Start two controlled Python nodes with known peering | Peer status evidence | Both peers authenticated/connected |
| 5 | Connect browser A and B to different entry nodes | DMP-C AUTH/STATUS evidence | Both UI sessions report connected |
| 6 | Pair QR and arm directional locators on both | ROUTE_ARMED evidence | Both entry nodes register inbound aliases |
| 7 | Run mutual probes and observe route state | hops/next-hop evidence | Destination/local route appears on both directions |
| 8 | Send A->B ciphertext and ACK | PWA B decrypts, mailbox/ACK observed, no PHP | A->B PASS |
| 9 | Repeat B->A plus destination offline/PULL | retained mailbox then PULL/ACK evidence | B->A and offline flow PASS |
| 10 | Run a multi-path shortest-route graph | later short route replaces early long route in live nodes | DATA uses minimum-hop path |

## 22. Server Jcode starting instructions

1. `ssh ems-vps`, then **use a login shell**: `su - jcode`.
2. First read the **One-page handoff** at the end of this file.
3. Second read sections 10, 11, 13 and 20, not the entire repository.
4. Attach existing canonical session: `cd ~/D-MASH && ./dmash-jcode.sh`. Detach with `Ctrl-b d`. Check `./dmash-jcode.sh --status`.
5. Use `search -> narrow read -> diff -> act`. Inspect `README.md`, `transport.py`, `client_gateway.py`, `network.py`, `node_manager.js`, `core_engine.js`, and tests only as needed.
6. First task: define/execute M1 test topology, not a crypto/UI/routing rewrite.
7. **Do not touch yet:** provider profiles/env files, runtime service secrets, `setup_nodule.sh`, legacy PHP removal, T-Ratchet redesign, DHT, DSP/call expansion, production runtime folders.

## 23. Open questions

1. Does the current deployed runtime exactly correspond to the canonical source on every service? **UNKNOWN.**
2. Is PWA pairing locator derivation fully secret-bearing and interoperable after fresh independent pairing? **NEEDS VERIFICATION.**
3. Does DMP-C probe forwarding correctly converge in a real three/five-node graph? **UNKNOWN.**
4. What exact packet dedup/replay semantics apply across restart and route expiry? **PARTIAL/UNKNOWN.**
5. Does current T-Ratchet meet any formally stated security property? **NO EVIDENCE.**
6. Are PHP relay users still active and what data retention exists there? **UNKNOWN.**
7. Is Origin notification delivery actually enabled/operational for production users? **UNKNOWN.**
8. How should untracked `setup_nodule.sh` be governed? **DECISION REQUIRED.**
9. What production deployment promotion process prevents source/runtime drift? **DECISION REQUIRED.**

## 24. Final verdict

**Project state:** active prototype with significant implemented subsystems but incomplete core vertical acceptance.  
**Network state:** signed P2P plus DMP-C/opaque transport code exists; real browser mesh delivery is **NOT READY**.  
**Crypto state:** real primitives but prototype composition, no production-security certification.  
**Infrastructure state:** **SERVER READY** for autonomous development.  
**Test confidence:** medium for targeted unit/infrastructure evidence; low/none for end-to-end messenger transport.  
**Next milestone:** M1 real no-relay PWA -> Node -> mesh -> Node -> PWA vertical slice.  
**Migration:** COMPLETE for engineering environment.  
**Product transport:** NOT READY/NOT ACCEPTED.

## 25. One-page handoff

**What D-MASH is:** a browser messenger prototype with a Python peer-node mesh direction, opaque locator transport work, legacy PHP compatibility relay, and optional Origin notifications.

**What works:** PWA shell/node selection, authenticated DMP-C control gateway, Node identity/P2P handshake, blind locator persistence, mailbox/PULL/ACK code and unit tests, Origin notification/vault unit tests, server Jcode/Nodule/GitHub/tmux environment.

**What does not yet work as accepted product behavior:** a real encrypted browser A->Node A->mesh->Node B->browser B delivery, reverse direction, multi-hop shortest path, offline browser mailbox recovery, and proof PHP relay was absent.

**Current architecture:** PWA encrypts/signs; entry Node authenticates client and routes opaque packet; intermediate Node forwards; destination Node live-delivers/stores ciphertext; destination PWA verifies/decrypts/ACKs. Mesh mode must not silently use PHP. Legacy mode still can.

**Current head:** `main` `05b10849937cf7cc3e629295d4233befadcfe938`, canonical repo `/home/jcode/D-MASH`, one tmux `dmash-jcode` session.

**Next milestone:** M1 no-relay real browser mesh vertical slice.

**First task:** make a reproducible two-browser/two-node acceptance topology with PHP relay instrumented/blocked, then run A->B and B->A.

**Do not regress:** explicit legacy mode, no silent fallback, no recipient user ID in DMP-C DATA, no raw locator persistent storage, Node does not decrypt payload, ACK after PULL.

**Do not touch yet:** provider profiles/secrets, runtime services, legacy PHP deletion, T-Ratchet/crypto redesign, DHT, PoW expansion, DSP/call/UI expansion.

# Recorded notes over EMS S-TURN — candidate

New `voice` and `video_note` sends retain an encrypted sender intent and local history before attempting delivery. They do not enter the old Mesh fragment queue. The generic outbox explicitly skips both `turn_note_v1` and historical `media_outbound` rows. Existing fragment rows remain readable and continue their original authenticated completion/retry path; final receipts now update the visible status in place.

## Wire and delivery boundary

Only Account-encrypted `voip_note_request` metadata (stable note ID, media kind, bounded manifest/hash, ephemeral signaling invitation) and `voip_note_complete` receipts use ordinary message transport. Binary media uses FileSession's ordered reliable RTCDataChannel with `iceTransportPolicy: relay`; 32 KiB FileChannel chunks receive application AES-GCM protection and a whole-object SHA-256 check. EMS `can_relay_blob` remains mandatory. The runtime does not bypass a false capability or silently fall back to Mesh fragments.

A known authenticated contact with an unlocked Account automatically accepts a note up to 2 MiB, with no autoplay. Larger notes up to 16 MiB require explicit acceptance. At most two incoming sessions and one outgoing session run concurrently. These are scheduling/memory limits, not the old two-recording enqueue limit. Local sender intents are bounded by 128 MiB of retained payload. A real storage/quota error is reported in Russian; existing data is not cleared to obtain a successful write.

`FileChannel.onCommit(blob)` is awaited after authenticated chunk/whole-file validation and before the final encrypted ACK. For notes, this commits receiver history and a pinned receipt record. Sender completion retires only its duplicate outbox payload, retaining history. A lost final ACK is recovered by another encrypted invitation: the receiver verifies the same note ID/hash/kind/size/MIME against its committed record and returns an authenticated metadata receipt without receiving a duplicate media object.

## Offline and cancellation

An offline/capability-unavailable send remains `waiting` on the sender. Bounded invitations retry with a 30-second initial backoff, rising to five minutes. No media bytes leave through ordinary messages. A fresh signaling session/key/nonce is generated for a new attempt; this is not an exact-ciphertext-resume protocol. Reload repairs a missing history row from the durable sender intent before any network use.

Cancel stops local signaling/RTC and retains the encrypted draft and history; it cannot retract a note already received. The UI says so and provides an explicit retry. Account switch/root lock closes sessions. Alias derivation, AES key and IndexedDB handle are captured; storage helpers are pinned and guarded around awaits so an old attempt cannot write through mutable new-Account storage.

## Evidence and limits

- Baseline .26 actual UI: 2.3-second voice, 13 Mesh fragments, approximately 54 seconds to receiver/receipt. The third consecutive recording was rejected after capture by `Recorded-note queue full`. A delivered record remained visually queued until reopening the chat.
- UNIT: FileChannel durable-commit-before-final-ACK; new note no-Mesh-fallback/generic-outbox isolation; legacy fragment retry/crash/receipt preservation; existing file runtime, lifecycle and key feedback.
- BROWSER storage mechanism: real AES/IndexedDB, three offline notes, reload, cancel retained content, retry, root lock and a deliberately suspended old-Account write rejected after the captured key changed. No service/UI delivery claim from this fixture.
- BROWSER actual EMS mechanism: real MediaRecorder, production WebSocketSignaling.create, FileSession/FileChannel and forced TURN candidates on both sides. Observed 2.3-second notes (about 29 KiB) completed in 3.9–8.0 seconds after enqueue. Only a 778-byte metadata callback crossed the synthetic Account transport boundary. This is not ordinary UI or deployed-capability acceptance; that remains a separate required gate.
- New source is isolated from the owner-acceptance hotfix. No production configuration or user profile was changed by this implementation work.
- Full ordinary UI voice/circle/offline/Account-switch acceptance and exact deployment checks remain pending until separately recorded. N0–N8 completion is not claimed.

## Candidate acceptance matrix

| Scenario | Current evidence | Remaining gate |
| --- | --- | --- |
| Three retained recordings without old queue cap | BROWSER real encrypted store PASS | Three actual UI recording/SEND actions NOT RUN on candidate |
| Online delivery | Real EMS relay/relay + hash + durable final ACK PASS, 8.0 s latest capture | Ordinary UI over real Account transport NOT RUN |
| Repeated invitation after lost final ACK | Real EMS mechanism with deliberate single final ACK loss, one receiver history PASS | UI interruption/recovery NOT RUN |
| Offline/reload/cancel/retry | Real IndexedDB/AES BROWSER PASS | Ordinary Account UI/reload NOT RUN |
| Account switch during pending write | BROWSER captured vault guard PASS | Full Account switch UI NOT RUN |
| Peer deletion while async work pending | BROWSER stale peer generation revoked PASS | Actual deletion UI NOT RUN |
| Existing fragment rows | Legacy real-crypto UNIT retry/crash/receipt PASS; generic queue excludes both row types | Retained old-profile UI migration NOT RUN |
| Video circle | Same bounded transport implementation | Actual recording/receiver playback NOT RUN |

Fixture-only failures during preparation: an asynchronous Playwright predicate returned early (replaced by awaited polling); one local test server omitted UTF-8 and garbled a Russian error assertion (header fixed). Neither was reported as a product delivery PASS. The candidate production source uses the normal PWA UTF-8 document.

Evidence source-hash note: the lost-final-ACK run was captured immediately before a one-line pre-decode 16 MiB base64 length guard was added. Its recorded hash is intentionally retained. The normal relay and offline/pinned-vault runs were repeated with the final guard. No production UI acceptance is inferred from either mechanism.

Follow-up MIME pin: encrypted receiving reservations and committed receipts now require the original MIME on retries. UNIT real-AES pending/committed substitution checks preserve the exact encrypted row; a real EMS lost-final-ACK run injected a changed-MIME retry and refused it, then accepted the original retry with one receiver history row. `qa-note-turn-mime-retry.json` records the exact new source hash. Its 54.4-second fault-recovery total includes the deliberate ACK loss, 30-second backoff and variable signaling admission work; it is not a normal online latency benchmark.

## Admission cancellation follow-up

Optional `AbortSignal` now closes signaling during connection, challenge wait, or admission hashing; recorded-note task teardown aborts its controller synchronously before session cleanup. Cancel stops admission before awaiting the encrypted-row update; the retained payload is unchanged. Root lock, Account teardown, and contact revocation use the same task teardown. Existing callers without a signal remain supported.

Validation: `call_signaling_abort.test.js`, existing `call_signaling.test.js`, and `recorded_note_mime_retry.test.js` PASS. Real Chromium `test_signaling_abort_browser.cjs` received an EMS WSS challenge and aborted on invocation of the first native proof digest (instrumented cancellation timing, unmodified digest/challenge). Socket CLOSED, promise rejected, CREATE only; no PROOF. Initial timer-based attempt had already sent a valid PROOF before the timer fired, so it did not establish cancellation-during-work and was replaced by the precise timing fixture. Evidence: `qa-signaling-abort.json` with source hash. Browser AES/IndexedDB `test_recorded_note_turn_browser.cjs` rerun PASS for three durable notes, reload, retained cancel/retry, offline no-media, root lock, and captured Account write rejection. This is mechanism acceptance; ordinary UI Account switch/cancel during real admission remains a separate release acceptance check.

## Receipt ownership cleanup

New encrypted receiving/committed receipts contain `peerId` and `noteId`; duplicate invitations must match both when present, plus the pinned MIME/hash/size/type. Existing contact deletion now identifies these records using its existing peerId filter. No Core/Storage deletion rewrite. Earlier anonymous candidate-only receipts remain encrypted and are not assigned an inferred owner or swept; production had not shipped this receipt format. Browser real AES/IndexedDB fixture validates committed receipt creation, contact deletion, re-add without inherited receipt, and preservation of another peer's receipt. FileSession commit is injected in this store fixture; real contact-menu clicks remain UI acceptance. Unit owner/note substitution rejects without changing ciphertext. Evidence: `qa-note-turn-receipt-delete.json`. First fixture run used an incorrect putBox test argument and failed before deletion; corrected test uses actual Storage API.

## Reload controls hydration

Both initial `selectPeer` history rendering and paginated `loadChat` now restore recorded-note status and cancel/retry controls from the captured Account's encrypted outbox. Hydration does not depend on starting a network task, so an already connecting task cannot hide the controls. Captured-vault/peer guards prevent hydration after an Account or peer change. Browser store fixture reloads the same IndexedDB, uses the actual Core status renderer in a small synthetic DOM, clicks Cancel/Retry, and checks the controls; this supplements the full application UI regression, which the UI tester reproduced on the prior release candidate. Core lifecycle tests PASS. Evidence `qa-note-turn-hydration.json`; this fixture is not a full Account login/browser-menu claim.

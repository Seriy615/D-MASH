# Independent S01 foundation review

20 October 2026. Reviewer: delegated `gpt-6.1-sol`, independent of the source author. **Scoped foundation review accepted through `1853bb0`, with the `176ae36` affirmative-inventory/journal delta reviewed and tested. This does not close S01, caller integration, the all-controls gate or native application acceptance.** No product source was changed by this review.

Inputs were read from immutable Git blobs: initial `7d153b134657ac847279024bcf4cf694c41c8072`, corrective `1853bb0`, and delta `176ae36bd8e4bfbfe48e7d6f999fda798d52fafc`. The frozen [master-secret design](../../audits/2026-10-20/verification/MASTER_SECRET_FIX_DESIGN.md), DeviceRoot, LocalCredentialService/worker and new foundation/vector/schema/wipe/cross-context/biometric-proof tests were reviewed. Source was copied outside the checkout before adversarial execution; concurrent author edits did not change tested inputs.

## Findings and disposition

| ID | Observed counterexample / source path | Corrective verification |
|---|---|---|
| R1 — new-wrap reopen | `7d153b1` `_encryptRoot`/`commitPreparedCredentials` accepted one transient wrong KDF result of valid length and immediately replaced canonical credentials. Once the instrumented adapter resumed correct output, both old/new master failed. This violated the required independent RAM reopen before CAS. | `1853bb0` independently re-derives/decrypts the v2 wrap and compares the same root before returning persistable output. Injected fault now rejects; canonical record remains byte-identical and old master opens. PASS. |
| R2 — self-cancellation | Already-unlocked `LocalCredentialService.unlock` called `_replaceState` → `lock` → service cancellation, then still published a new state. Treating all cancellation as external would misstate this behavior. | Same-root reauthentication now compares actual root bytes, retains the active state/epoch, updates metadata and disposes the prepared copy. No synthetic lock/cancel cycle. PASS. |
| R3 — revision validation | String `1` became string `11`; negative/NaN were accepted; MAX_SAFE overflowed and the next unsafe revision could remain unchanged. This was an integrity/CAS guard defect, not a master-password bypass. | Raw IDB corruption injection: string/negative/NaN/unsafe values reject STORAGE_CORRUPT. MAX_SAFE is readable but its next write rejects CREDENTIAL_CONFLICT. PASS. |
| R4 — credential schema | Unknown version/ready or unknown cleanup/invalid wipe profile could publish; unknown state looked like pending setup. | Unknown version/state/cleanup/wipe structure rejects before publication. Legacy absence remains explicit; modern wrap KDF profile is exact. PASS. |
| R5 — pre-intent cancellation | In the coordinator draft, pausing initial control.put before its durable write, aborting and releasing still completed deletion. This was cancellation before durable intent, not a request to undo an accepted wipe. | `1853bb0` passes signal/current into the real initial intent transaction; cancellation aborts it. Fixture now returns CREDENTIAL_CANCELLED with zero shutdown/cleanup calls and retained sentinel. PASS. After actual commit, caller cancellation intentionally cannot promise rollback. |
| R6 — cross-context ordering | A process-local singleton/onLock test cannot establish fencing across independent Root instances. Separate credential/wipe lock names would leave a setup-KDF/finished-wipe window. | Two real Chromium pages, independent Root/Service globals, actual navigator.locks and IndexedDB: wipe is pending on the same installation lock behind paused setup; release permits setup then wipe; no root survives/publishes, stale store rejects ROOT_STORE_INVALIDATED and only the control DB remains. PASS on both `1853bb0` and `176ae36`. |
| R7 — affirmative inventory | A direct prepareSetup callback returning false/undefined was not independently required to affirm emptiness. | `176ae36` rejects both with LEGACY_MIGRATION_REQUIRED, no root allocation persisted. Positive service setup still works in the two-page test. PASS. |

Additional journal-shape advisory was sent to root: a contradictory complete marker (ancillaryComplete false or undeleted named DBs) should not be recognized as a consistent completed wipe. The `176ae36` delta already rejects unknown marker versions/states, invalid names and deleted entries outside the inventory. No password bypass or new deletion was demonstrated by this advisory.

## What the evidence establishes

The shipped IndexedDbDeviceRootStore now performs read, expected-proof/changed-slot comparison, merge and write within one readwrite transaction; there is no await between read callback and write. The process-local write queue is not the cross-context authority. Independent Node/fake-indexeddb fixtures passed 16 simultaneous unrelated-material pairs and one-winner biometric conflict. A separate **real Chromium IndexedDB** harness on `7d153b1` passed 32 overlapping pairs, conflicting biometrics and cancellation preserving canonical bytes. These storage harnesses are not UI acceptance.

The actual bundled WASM vector suite passed independently on both `7d153b1` and `1853bb0`: deployed mislabeled legacy Argon2d reads, explicit Argon2id v2 writes, same Root/DeviceID/opaque encrypted-material record retention, and exact-profile rejection. No global alias or Account KDF/identity derivation change was introduced. New v2 uses type 2, Argon2 v19, time 3, mem 65536 KiB, parallelism 1, hashLen 32; root salt remains UTF-8 canonical base64 of 16 random bytes. Legacy d/id probing is bounded and requires successful complete AES-GCM authentication. V2 uses a separate authenticated wrapping domain.

Prepared handles expose only public DeviceID. Lock/dispose invalidates generations and clears prepared root/identity secret byte buffers. A post-commit abort fixture retains the committed revision while preventing prepared-root publication. Pending setup persists one canonical encrypted root and ordinary unlock never allocates a missing root through the new service. A worker/native KDF port is required by the service; unavailable inter-context locking fails closed. Strings cannot be guaranteed zeroed in JavaScript; byte buffers and worker lifetime are managed, and no PIN/root plaintext is logged/persisted by these new modules.

The actual persisted wipe profile tag is `sha256-prehash-argon2id-v1`, salt input `dmash/local-wipe/v1|` plus canonical base64 random16. Native test vectors/callers must use that exact tag; the frozen design contains an earlier spelling with an additional `wipe-` prefix. The service accepts 4–64 digits; current calculator bounds remain a separate UI policy. These exact contracts should be reflected in current integration documentation, without editing the frozen audit.

## Required integration limits

Loader/UI/calculator/Core settings, v50 repair, v54/v55 emergency aliases and existing biometric overrides still require migration to these APIs. In particular, existing `DeviceRoot.unlockWithWebAuthnPrf` and loaded runtime/v50 replacements are not made safe merely by adding `prepareWebAuthnUnlock`. This review accepts the new prepared primitive; it does not claim every legacy entrypoint is fenced. Real browser flows must retest those actual loaded wrappers after composition.

Credential change can commit a NEW master before legacy localStorage cleanup fails. Callers must distinguish committed-change/cleanup-pending from precommit failure and avoid implying the old master remains authoritative. This was sent to the author for typed result/error integration. The cleanup-failure migration test alone is not proof of that UI behavior.

Wipe is resumable across DBs, not atomic across origin storage. After durable intent it needs intentional runtime shutdown, cross-context invalidation and explicit authenticated/full-reset recovery if root deletion precedes a failed completion-marker write. A deleted master must not become the sole way to authorize that explicit recovery. The coordinator's caller wiring and complete adapters remain integration work.

Physical WebAuthn/PRF hardware, OS-keystore behavior, native Android/Windows/Linux clients, positive external transport and all-controls acceptance were not run here. The worker crypto boundary is reviewed source plus bundled-vector evidence, not a native implementation or a claim that every current KDF caller already runs off the UI thread. No full-runner PASS is added by this review.

## Reproduction and provenance

Node v24.19.0; Chromium 156.0.8078.4. Adversarial cache: `/home/jcode/.cache/dmash-s01-review-20261020/`. All data is synthetic. `adversarial.cjs`/`schema.cjs` reproduce original failures; `final/` repeats against `1853bb0`; `delta/quick.cjs` and `delta/two-context-wipe.cjs` test `176ae36`. KDF fault/scheduling fixtures use an explicitly instrumented deterministic port, not a substitute Argon2 proof. `vendor-review/tests/local_credential_vendor_vectors.test.js` executes the actual vendor WASM. Browser storage fixtures allow loopback HTTP only, block all WebSockets and ServiceWorkers, and directly exercise store APIs; they are not counted as button clicks.

Source hashes:

| Commit | device_root.js SHA256 | local_credentials.js SHA256 |
|---|---|---|
| 7d153b1 | a23e4765862e71d23e05316175cd4b904f7811c091c989882b3708c3db23a6f4 | 926a31dbb4e45fbd51ec589748bb43410dbf3df3c7e8442293174bbf30c87674 |
| 1853bb0 | 1828954c4a7c2e67a79a4c8ce2caed6a40fc69013c67c664e51feb92835b121e | 133b3c45c5002adccdcc267da45474c9f40b94541064d064f24365c16a2b32b2 |
| 176ae36 | bd16ff2a0857d4dafa091aac4d4c50fd5e23967ef90e0a62cd0d319cdf88eed5 | ab47329b380b5b2dbee7c637b06ac1dd9008f3d7340e56d50a6ee6a418eef46c |

Adversarial artifact hashes (persistent cache, paths relative to the cache root):

| Artifact | SHA256 |
|---|---|
| adversarial.cjs | 0c3737c0dadc07953799d63ea81e21f14088f56010a15341f4a3018be3431fbb |
| results.json | 809125afe599b915a0997f408d829af04692b17e719f623ba39c4c3c65603368 |
| schema.cjs | daacae8be686fe0e813e4d77431b8dab848a0b68d3561071dcea20ed62ae8325 |
| schema.json | 79c7bbe333dc2e2ff2bada68de98a7c4985df1ab868a0d0b9ea4f6ee0e73386f |
| native-idb.cjs | d8b55ee287376a93d0920ae25743d4c75a876ffb6618a1f6c152fefa2507fb9f |
| native-idb.json | 0c9bcb3f37a9b8c33d189facc08d73c8dad99fe4aaace80090b662bbcd94c04d |
| pre-intent-cancel.cjs | 1feefc72300d1d5cad055645ceffb1aac3cf1f4fbcaa60026eafbc2f3444e14b |
| pre-intent-cancel.json | 80ca1fdcb78606783c577981392dabfdaa3870dcf20b46177cccdc19d237aa50 |
| final/adversarial.cjs | 70931a987a9e38778bedb4221e4d31e36fdcb67f5e678c30c3f57cdeb851fd0b |
| final/results.json | 35c1cdd6c01ea7a5f0c188f0c95bd02675bbca620ceb55d57283f8fa26849298 |
| final/schema.cjs | ae3486621c277597977f8860665ed8f3d9eb5dc293cd3ef12485e390c0290860 |
| final/schema.json | 1f3b99df679cc295308180a2d3b398d9e48309fbbc7da7aa259fe4a66f8a57b4 |
| final/pre-intent-cancel.cjs | 47994af518b5a8a7750b99cf4258371e45c7565bc3c7e71d83f98cc1b36d994a |
| final/pre-intent-cancel.json | bbc64b52f70b5c297b6ba3a0eb6db52119b8f284fe27220215e375b717fd1644 |
| final/two-context-wipe.cjs | 0a40dc7a8b69a16536d889e30f2b32d5305522d9552add82336c8f20acc62542 |
| final/two-context-wipe.json | 3bc41521a675bf1b1f3a4d798453fe2a1889383789101dd54be9e1db4c8b85ec |
| delta/quick.cjs | fa0f79f8d30518f7e13bfb0d4decb3b9157c5db9e6889b3ac3c57b87ef4dd082 |
| delta/quick.json | 67a718acb1acaf147055e9b140038ff4af0a6be6e8301daab9ffbe6943def6f6 |
| delta/two-context-wipe.cjs | aa1c948b8ba02fe8c789fcc231d398b9ed5a404ac85e61600ec8c3a510dd65bd |
| delta/two-context-wipe.json | 232bf2d1bf2f35ad8a428b143250513c23348e97e78087268b0611f9da716d0e |
| vendor-vector-7d153b1.log | bdac3b6025af4c67a1bc46b6b17b1b07788b8a116ba3bb1755acb9b438c96165 |
| vendor-vector-1853bb0.log | bdac3b6025af4c67a1bc46b6b17b1b07788b8a116ba3bb1755acb9b438c96165 |

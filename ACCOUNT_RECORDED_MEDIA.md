# Recorded-note transport — PARTIAL Account implementation, EMS candidate acceptance PASS; published acceptance pending

The previous inline recorded data path exceeds the frame bound even for a short video.
`tools/diagnose_recorded_media_size.cjs` reproduces 33700 recording bytes becoming
a 90627-byte signed Account envelope. Do not raise the Node/Device frame bounds
or treat an endlessly queued oversized packet as successful note delivery.

The intended owner is an Account module, outside Node/Worker transit. Reuse the
existing signed Account E2EE/ratchet and ordinary opaque local submit pipeline;
no new cipher or Account identity field is added to Node routing metadata.

Before sending fragments, negotiate an authenticated, transfer-bound version-1
note profile. Reserved `voip_media_profile_request/response` controls travel in
existing encrypted media-control packets; older receivers ignore the unknown
control without rendering fragments as user messages. A DELIVERED receipt for
the probe is not profile support. Require a fresh, matching authenticated
response, bounded timeout/retry, and fail closed for unsupported/unknown profile.
No unsupported recipient receives a fragment stream or a silent downgrade.

Version-1 fragments contain transfer ID, index/count, encoded size and SHA-256,
media type/name/MIME and bounded data slice, all inside signed Account E2EE.
Use stable per-fragment logical wire IDs and one separate final-history wire ID.
Bound each plaintext slice so its actual serialized/cipher/envelope size fits
both current v3 and v4 limits. Verify the resulting bounds, not only raw length.

Sender intent, source data, progress, profile state and retry timestamps persist
in the Account-encrypted outbox before transmission. At most eight fragments may
await peer persistence receipts; local Node acceptance does not free that window.
Avoid filling offline/locked recipient queues with the entire note. Lost receipt
retries reuse logical IDs. Completion requires peer persistence of every fragment
and one verified final-note receipt; cancellation and 24-hour expiry are explicit.

Receiver assembly persists in Account-encrypted storage. Verify authenticated
peer, Account generation, immutable manifest, fragment count/length and final
digest. Bound assemblies per peer, total bytes and expiry; reject conflicting
duplicates and malformed input without blocking unrelated messages. A fragment
receipt follows its durable write. Completed assembly saves exactly one ordinary
voice/video-note history entry; fragments and profile controls do not enter chat.
Crash after history commit before Inbox retirement/receipt cannot duplicate it.
Account logout/root lock cancels in-flight work without exposing plaintext to Node.

The current encoded DataURL note bound is 16 MiB, with four active assemblies
total and two per peer, a 32 MiB reserved receiver budget, and 64 ledger entries
including completion tombstones. Expired transfers are purged one per sync pass.
These limits still require real browser/vault/Inbox quota acceptance.
Keep the existing separately consented generic file-transfer path independent.
Implemented in account_recorded_media.js with explicit Core/Account storage
injection. Frame limits are unchanged. Local tests use real Account ratchet,
signatures and recipient crypto, controlled transport and in-memory persistence;
they prove fragment/window/loss/restart/digest/history/profile/storage-failure
behavior, not production Node transit or mobile persistence. Core captures the
recording recipient and Account generation before permissions, binds recorder
and FileReader callbacks to that context, and releases late hardware grants.
The release loader and Service Worker include the module. Real two-Account
Chrome candidate acceptance through EMS PASS: actual UI-recorded voice (17942
encoded characters) and video-note (259034 encoded characters), real encrypted
transport, one receiving Gamma history row, actual playback advances and final
receipt retires the outbox (`/tmp/dmash-recorded-media-ems-candidate.log`).
Microphone/camera are synthetic. Private route readiness initially failed and
recovered through existing retry; immediate readiness is not claimed.
Crash tests also cover intent-before-local-history and receiver-history-before-
assembly-completion writes. This does not prove every production crash window,
mobile quota or full v4 UI cutover. Preparing release .24; deployed acceptance
remains pending.

Required evidence: real Account/recipient crypto; offline sender/recipient and
locked different Account; loss/duplicate/reorder of every fragment/receipt; crash
and restart at persistence transitions; wrong peer/Account, malformed manifest,
conflicting fragment and quota/expiry; profile refusal for old/mixed versions;
real browser recording delivered through EMS and playable at the receiving side.
Exercise both explicit v4 sender and the bounded v3 migration adapter. A local
Blob-player test proves playback only and cannot close the transfer requirement.

Release validation .24: 264 backend + 11 Origin + 67 JS suites PASS
(`/tmp/dmash-recorded-media-release24-all-tests.log`), manual source review,
diff whitespace and credential-pattern scan PASS. Existing ciphertext/schema
remain readable; new Account-owned rows are additive and encrypted. Frame
bounds, keys, peer identity and Node wire metadata are unchanged. No browser
vault migration/deletion is performed. During rollback do not discard pending
media rows or downgrade an active transfer to an older outbox reader; retain
encrypted state and resume .24 to settle it. Existing public/private route and
ratchet recovery limitations remain independent work. Published version .24
and active SW exact-source acceptance must still be checked after deployment.

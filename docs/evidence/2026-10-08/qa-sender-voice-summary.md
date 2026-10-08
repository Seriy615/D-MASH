# Deployed voice baseline (2026-10-08)

Synthetic fresh PUBLIC pair, actual Request/Accept/Confirm/key exchange then fake-microphone record/SEND/decrypt actions. Page and service worker on both profiles: `transport-v3-node-preparation-20261008.26`. All 131 captured loaded resources match `3c513601ef3990b6514e247d879324b7b72da494`. Browser retained at CDP9452 for authorized handoff; user CDP9449 untouched.

Initial contact harness was interrupted by an incoming notification replacing the settings modal. The same profiles were resumed by actual clicks; original deadline failure was not converted to PASS. [Resumed evidence](qa-sender-voice-deployed26-resumed.json): 9 PASS, 1 FAIL.

- First recording started 02:14:15.268, queued 02:14:18.429 (13 fragments). Recipient audio readyState4, duration2.721s at 02:15:11.965: about53.5s queued-to-ready.
- Authenticated final receipt at02:15:12.979 removes outbox and sets history DELIVERED, but visible sender ⌛ remains at02:15:15.999. Local decrypt works; actual chat reopen at02:15:16.472 displays ✓✓. Thus stale delivery UI is proven; literal encryption/decryption hang is not.
- [Three-recording burst](qa-sender-voice-burst26.json): first two records accepted (12 and11 fragments), third SEND at02:18:10.655 shows `ЗАПИСЬ НЕ ОТПРАВЛЕНА / Recorded-note queue full`. No durable third note or retry control.
- Both accepted burst records eventually complete and retire; history DELIVERED but both visible sender rows stay queued. Final complete observations:02:19:03.330 and02:19:16.989.

[Metadata-only protocol observation](qa-sender-voice-burst-observation26.json) separates negotiation and transmission: first profile request02:17:59.420; recipient request02:18:00.668; response02:18:00.683; sender response02:18:02.921; first fragment02:18:04.199, subsequent fragments roughly1–2s apart. First profile-to-complete about64s. No content, cryptographic keys, transport payloads or identities were recorded. File hashes are source provenance, not identities. CDP logpoints may affect timing: this is a diagnostic baseline, not a benchmark or proof that all time is encryption.

Source localization: `account_recorded_media.js` completion updates persisted transport state and retires outbox without refreshing sender row. Queue admission rejects above2 operations per peer before saving recording; recorder path then discards capture state. Fix owner `qa_account_media` prepares dedicated S-TURN media channel. No runtime code was changed for this baseline.

Next acceptance (NOT RUN): three consecutive voice and circle notes; capture cancel; explicit pending/loading/progress/cancel; offline peer → durable waiting → reload → recovery; final sender receipt without reopening; receiver decode with no autoplay; content hash equality; relay statistics and proof media bytes use S-TURN rather than Mesh DATA. Physical microphone quality, physical mobile browser and old-client compatibility remain separate NOT RUN.

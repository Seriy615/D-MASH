# `.30` live test Account history safety check

Deployed PWA source `22c699d6575fe2ba977db44264d8df0062b14799`;
page and active controlling service worker both
`transport-v3-node-preparation-20261008.30`. Read-only EMS source verifier:
256/256 matched, no missing or changed files. The test used the existing
live Codex Account profile; no browser storage reset, identity regeneration,
contact reimport or secret rotation occurred.

Before repair, the encrypted Gamma vault had one peer, three message rows,
one secrets row, and `msgCount=0`. The pre-repair raw encrypted vault was
saved outside Git with mode `0600` and SHA-256
`be6dafef7fc1043233d2c7876f44e6bd90d1c7b20663f373790a66fdecd98238`.
`Storage.inspectHistoryCounterGamma(peer, 3, 0)` returned a single-peer,
contiguous, decryptable ownership proof. The explicit guarded CAS repair
changed only that secrets row to `msgCount=3`; byte-for-byte comparisons
confirmed the three ciphertext message rows and encrypted peer row unchanged.
The Account ID, local pairing contribution and peer pairing contribution
matched their pre-upgrade values. Three messages were visible after an actual
peer click; the incoming voice row decrypted through its visible button.

One actual SEND click then appended sequence 4; all three earlier rows
remained. The new message was visible with local `SENT` state. This is **not**
an authenticated delivery or read receipt, and no recipient acknowledgement
was observed at this checkpoint. No duplicate test message was sent.

Limits: This was a single existing test Account and a manual, narrowly proven
counter repair. It does not establish general automatic migration, N4
one-sided recovery, ordinary v4 Node UI cutover, or mobile behavior. The
repair command must not be generalized to multi-peer/gapped/locked vaults.

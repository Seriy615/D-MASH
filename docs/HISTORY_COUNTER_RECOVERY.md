# Gamma history counter recovery gate

An Account key exchange previously replaced the whole `blind_secrets` record
with `msgCount: 0` in both the incoming 0x01 and 0x03 paths. Existing encrypted
`blind_messages` rows stayed in IndexedDB, but ordinary history pagination
could not see them. The next legacy `saveMessageGamma` could overwrite sequence
1. The key exchange now commits changed crypto fields with a ciphertext CAS
and retains the latest message count and unrelated fields. Message append is a
single three-store transaction with exact old-owner CAS and a check that the
next message alias is empty. It refuses a stale/colliding counter before
writing any row.

For a known single-peer vault with `msgCount: 0` and exactly three contiguous,
decryptable message rows at aliases 1–3, use the explicit read-only
`Storage.inspectHistoryCounterGamma(peerId, 3, 0)`. The method checks current
Account/vault references, authenticates the peer row, counter and message
rows, requires no chat lock, and requires that **all** raw `blind_messages`
rows belong to that contiguous sequence. It returns counts only. Any gap,
extra row, corrupt ciphertext, changed Account, or different count rejects.

`Storage.repairHistoryCounterGamma(peerId, 3, 0)` repeats that proof and then
compares the exact encrypted peer, secret and all message rows inside one
readwrite transaction. Its only write changes the existing encrypted secret
record's `msgCount` from 0 to 3; other fields and every historical ciphertext
remain unchanged. It is never called automatically. A fresh encrypted raw
vault backup, user-Account owner verification, source/deployed SHA check, and
read-only inspection must precede any live invocation. If any check differs,
stop; do not reset or import a new vault.

The strict single-peer scope is intentional. Other peers, gapped history,
locked chats and unknown raw rows require a separate authenticated recovery
procedure. A repaired counter does not prove delivery or restore missing
remote messages. This change does not by itself migrate legacy chats to N4.

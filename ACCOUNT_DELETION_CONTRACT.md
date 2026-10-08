# ACCOUNT-DELETE-01: local Account deletion boundary

Product baseline: `042d5803d5d622da72848c67d96bd5c8243c4819`, page/SW `.32`.
This task does not complete Account erasure, N3, N4, N5, or N8.

## Confirmed source defect and interim contract

`Core.removeAccountFlow` deletes the root-encrypted registry entry, asks IndexedDB to delete an invented `dm_v6_*` database without awaiting completion, and claims that history and keys are fully erased. The actual Account vault is the shared `dm_gamma_vault` with five stores. Removing its database would erase other Accounts. Removing only the registry also removes the saved signing-identity pin used by `Core.boot` before installing candidate keys.

The Account AES key is derived from its credential and identity via Argon2; root-encrypted registry and Inbox/route/contact-flow records have different owners/keys. Legacy Kyber material is shared under DeviceRoot and must not be deleted for one Account. Successful decryption of some vault rows proves membership for those rows, but cannot classify failed-decrypt rows as foreign versus damaged target data, establish completeness, or retire route/Inboxes safely.

Interim behavior: refuse the destructive UI action and state explicitly that the Account, keys, and history are unchanged. Do not remove the registry authentication pin, delete any database, or replace identities. Do not relabel the old deletion operation as a harmless hide action: a hide feature would need to retain the encrypted identity pin separately. Full erasure remains OPEN. Accounts already removed from the registry by older builds are not silently reconstructed by this patch; their retained ciphertext and missing pin need a separate authenticated recovery/migration path.

## Required authenticated migration for actual deletion

1. **Credential and generation proof.** Capture root state, selected Account ID/signing public key, vault key/DB, session generation, and cancellation signals. Derive the candidate credential without installing it, compare the saved signing identity, and bind authorization to a fresh deletion operation ID and exact Account generation. Wrong credentials, another Account, lock/switch, or changed registry must leave state unchanged. A DeviceRoot unlock alone is not the missing Account ownership proof.
2. **Complete versioned ownership inventory.** Introduce an authenticated per-Account manifest covering Gamma peers/secrets/messages/outbox/pairing records (including alternate history-password aliases and opaque v4 formats), registry auth/biometric records, root Inbox route policies/pending envelopes/contact-flow state, local managed route bindings and grants, and notification associations. Shared DeviceRoot/Node/legacy KEM material is explicitly excluded. Root-neutral public intake routes and requests must also remain unless an authenticated record proves exclusive ownership by the deleting Account; a selected acceptor does not own the global public intake. Future N7 `blind_files`/`blind_file_owners` must be included through their Account-authenticated manifest when that schema is integrated. Each owned record needs authenticated Account identity/generation and alias/format binding. Scan/migrate legacy records using credential proof plus authoritative derivation; do not guess ownership of unreadable or unindexed records. Missing/ambiguous ownership blocks a claim of complete erasure and preserves records for recovery.
3. **Durable freeze and route retirement.** Persist a root-encrypted deletion intent with the exact verified inventory digest and Account generation. Quiesce Account writers, media/retry/session work and dispatch, await captured in-flight operations, and revoke late writes by generation. Record a tombstone before withdrawing local route ownership. Use genuine owner capabilities/proof to retire only that Account's routes; do not stop Node transit or other Accounts. Pending/late envelopes from the retired generation must not recreate deleted state.
4. **Crash-resumable per-store commit.** There is no global IndexedDB transaction across the registry, Gamma vault and root Inbox databases. Use explicit PREPARED → ROUTES_RETIRED → VAULT_ERASED → AUXILIARY_ERASED → COMPLETE stages with immutable operation/inventory digest and idempotent guarded steps. Gamma owned rows can be CAS-checked and removed in one transaction over its five stores. Changed/new records require rescan or abort before destructive commit. Never report COMPLETE after only one store succeeds. Keep the registry identity pin/tombstone until all mandatory stages are durably verified, then retain the minimum root-encrypted anti-resurrection marker required by the protocol.
5. **Recreation and limits.** Define an explicit fresh-generation recreation protocol for the same display name; old routes, frames and pending messages cannot attach to it. Current deterministic credential derivation can reproduce signing keys, so deleting browser records cannot truthfully mean that a remembered credential or external backup can never reconstruct a key. Do not silently rotate root/shared keys. Distinguish logical local record deletion from physical flash/backup erasure, which browser APIs do not prove.

## Required acceptance before enabling actual erase

Actual UI with fresh synthetic A/B: cancelled and wrong-credential deletion leave both unchanged; valid A deletion removes every inventoried A record and late-route delivery cannot restore it; B identity/history/keys/biometrics/routes remain byte-identical and usable. Include same-name recreation, reload/lock/Account switch at every await/commit stage, pending media/writes, shared peers with different per-Account aliases, password-protected history, corrupt/unknown-format records, storage quota/abort, and crash/reopen at every journal stage. Compare encrypted-row inventories without publishing keys/content. Prove Node transit stays live where required. Only then may UI state that local Account data was deleted; full crypto erasure/remote deletion is a different claim.

Browser baseline and interim refusal evidence will be attached separately; source findings are not a substitute for actual clicks.

## Actual browser baseline and interim retest

Fresh synthetic persistent Chromium profile, then the same retained profile; no user data/reset. Full source overlay from `.32` base above, page `.32`, SW BLOCKED, Chromium `156.0.8078.4`, 57 loaded local asset hashes recorded in each report, page errors 0.

- `qa-account-delete32-harness-race.json`: both Accounts/history created. First helper checked the asynchronously reopened registry before rendering completed after Cancel. This is a harness timing failure; assertions were changed to await the actual two-row DOM, and the same profile was resumed without reset.
- `qa-account-delete32-red.json`: 5 action checks PASS; product ACCOUNT-DELETE-01 **FAIL reproduced**. Real Cancel preserves database hashes, real confirm removes the registry entry, same-name/credential recreation shows the original Saved Messages history, and the other Account's history remains isolated.
- `qa-account-delete32-green.json`: 6 actual UI checks PASS. Delete shows the truthful unavailable notice without a destructive confirmation. Every IndexedDB store hash/count matches the pre-click snapshot. Both registry entries remain. The new-entry form with the same saved name and a wrong key refuses login; correct credentials reopen its history, and the other Account's history remains intact. The helper reads only encrypted database snapshots to hash them; those hashes supplement actual UI actions.
- `core_lifecycle_acceptance.test.js`: PASS including an explicit refusal check that rejects any Storage/IndexedDB access and any destructive prompt.

Reproduction commands from the isolated checkout (Node 24.19.0; browser/tool module paths default to the Forge test environment):

```bash
DMASH_QA_PROFILE=/tmp/dmash-account-delete-synthetic-new \
DMASH_QA_OUTPUT=/tmp/account-delete-red.json \
node tools/qa_account_delete.cjs
# After applying the candidate to this checkout, keep the same synthetic profile:
DMASH_DELETE_MODE=fixed DMASH_QA_RESUME=1 \
DMASH_QA_PROFILE=/tmp/dmash-account-delete-synthetic-new \
DMASH_QA_OUTPUT=/tmp/account-delete-green.json \
node tools/qa_account_delete.cjs
```

The baseline command must use unmodified `.32` source; running baseline expectations against the refusal candidate is intentionally incompatible. This is source-overlay acceptance, not deployed `.33`/SW acceptance. Full Account erasure is still OPEN, and previously removed registry pins are not reconstructed automatically.

# Contact acceptance owner preflight

The pending-request list is DeviceRoot-scoped, but a durable signed Accept belongs to its original Account. An interrupted send previously left the request visible for another Account; clicking Accept then exposed `Contact acceptance owner mismatch`. An outgoing/self request used the same raw error. Expired saved Accepts could also be resent without a useful explanation.

Before offering acceptance or the Account picker, Core now reads the existing encrypted flow. An outgoing request cannot be accepted locally. A reserved request names its original local Account and offers an explicit logout/selection action. The original Account can retry its exact saved Accept without another Quick Name prompt. An expired signature gets a new-request explanation; an established flow can finish the pending-list transition. ContactFlow retains its authoritative role/owner/context checks and additionally refuses expired saved Accepts immediately before sending. No saved signature, owner, identity, key or history is reassigned or regenerated.

## Validation

- UNIT: `contact_owner_preflight`, `contact_flow_owner_retry`, `contact_flow_v3`, `pending_contact_ui`, `pending_contact_requests`, `contact_bootstrap_v3` tests. The existing UI mock now supplies the mandatory read-only flow lookup.
- BROWSER: `tools/qa_contact_owner.cjs`, Chromium 156.0.8078.4, 7/7 PASS, source hashes in `docs/evidence/2026-10-08/qa-contact-owner.json`. Fresh synthetic A/B Accounts were created with actual UI. Actual menu/accept/error/logout/login/retry actions verified owner guidance, byte-identical retry, genuinely signed short expiry, outgoing/self guidance and preserved Saved Messages history.
- This is explicitly a supplemental fault-injection fixture: incoming metadata and failed/successful transport queue callbacks are injected; signatures and DeviceRoot encryption are real. No claim of a new remote delivery or deployed PASS. Full local PWA overlay, page .26, SW blocked. Existing separate two-profile transport acceptance belongs to the preceding key-exchange/Flip-Lock hotfix.
- First fixture attempts exited on test helper base64 encoding errors before acceptance, corrected before the two 7/7 browser runs. The final run includes the authoritative expiry guard. No production or user profile was accessed.

Run with Node 24.19.0 and Playwright installed:

```
DMASH_TEST_PWA_ROOT="$PWD/D-MASH PWA/not_messenger" node tools/qa_contact_owner.cjs
```

Integration note: the main-branch historical `contact_flow_owner_diagnostic.test.js` asserts the former expired-resend bug. On integration, update its expired branch to assert refusal/unchanged encrypted state, as the new `contact_flow_owner_retry.test.js` does; do not retain an intentionally failing historical expectation in the default suite. This release-parent worktree does not contain that later diagnostic.

Full Node Account cutover and N4 recovery remain separate unfinished work.

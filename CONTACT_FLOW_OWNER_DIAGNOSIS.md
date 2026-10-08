# Contact acceptance ownership diagnosis

Synthetic real-crypto diagnostic: `D-MASH PWA/not_messenger/tests/contact_flow_owner_diagnostic.test.js`.
Run with Node 24.19.0. This is UNIT evidence, not browser/UI acceptance.

A failed network send persists root-encrypted `contact-flow:<request_id>` with
`role=acceptor`, original Account slot and signed Accept before returning failure.
The global pending-request UI can still offer the request to another Account.
Both `accept_prepared` and `accept_sent` then produce `Contact acceptance owner
mismatch`. The diagnostic proves that encrypted rows and send count do not change,
and the original Account can resend the exact persisted Accept. An outgoing local
`role=caller` request produces the same error under either Account. A screenshot
alone cannot identify which case occurred.

Before offering acceptance or an Account picker, read the existing encrypted flow.
Unclaimed requests may select an Account. Claimed requests must resume only with
the authenticated original Account. Caller/self requests need an outgoing-request
explanation, not an acceptance action. Completed flows should expose completed
status. Recheck ownership at mutation time; preflight UI is not authorization.
Never change role, owner, signed Accept, or request ID implicitly, and never erase
the existing row to make another Account succeed.

Expiry has a separate reproduced bug: automatic resume skips an expired Accept
without updating its pending status, while explicit accept sends that expired
signed bootstrap and the receiving verifier rejects it. V3 route certificates
have no expiry field; bootstrap and route-grant expiry must not be conflated.
Show an explicit expired state and a deliberate new-request workflow. Do not
re-sign an old Accept silently: the peer may have saved its hash and CONFIRM binds
that hash. Preserve old records. A valid CONFIRM already durably received can be
completed by the original owner; that case needs its own regression test.

Required future browser acceptance uses synthetic Accounts: fail an Accept send
under A, switch to B and click acceptance, verify the visible owner explanation,
return to authenticated A and resume; repeat for accept_sent and outgoing/self.
Advance expiry in a test profile and verify truthful expired UX without invalid
network retries. Check cancel/loading/disabled controls and unchanged encrypted
ownership/history. These browser cases are NOT RUN in this diagnostic checkpoint.

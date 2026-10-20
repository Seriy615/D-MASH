# Account application outbox V4

An ordinary text send must survive a crash between UI history and Node submit.
`AccountAppOutboxV4` therefore commits an encrypted, per-peer operation intent
and encrypted pending index in one IndexedDB compare-and-swap transaction. The
intent contains the original text, operation ID, confirmed session ID and
generation, and signed binding digest/generation. It is local Account-vault
data; no plaintext is sent to a Node or stored in clear IndexedDB fields.

`AccountSessionRuntimeV4` requires both trusted callbacks for ordinary send:
`persistAuthenticated` for incoming history and `persistOutgoing` for outgoing
history. The outgoing callback must atomically and idempotently commit the
message under the operation ID with visible state **PENDING**, not SENT or
DELIVERED. Runtime stages the encrypted intent, calls `persistOutgoing`,
reserves a bounded retry time, then invokes `AccountAppCipherV4`, which
materializes and reuses one exact ciphertext frame before local Node submit.
If history persistence fails, the Node submit is never called. After a crash,
`runtime.resumeApplications(peer)` reads the pending index and repeats the
history callback and exact frame submit. `runtime.resume()` includes this
after handshake flush only when that peer is ESTABLISHED.

The queue is per Account+peer and bound to the original session and route.
Changed plaintext or context under one operation ID is rejected. A migration
or recovery to a new session cannot silently reencrypt a pending operation;
that requires an explicit reconciliation path. Retry reservations back off
from five seconds to five minutes, without a fixed attempt count. Up to 512
pending text operations per peer are accepted; this is a resource bound, not
recipient delivery. The result distinguishes durable local intent, adjacent
Node queue acceptance and `recipientAck: false`.

This slice does **not** yet implement an authenticated peer ACK, ACK_REQUEST,
or retirement of pending operations. A Node's queued/accepted response cannot
change history to delivered. The sender-held ledger must remain until a
separate authenticated receipt consumer retires it. Voice/video bulk bytes
remain on the S-TURN path, not this text outbox.

`account_app_outbox_v4.test.js` is UNIT evidence with WebCrypto and a synthetic
transactional IndexedDB emulator. Real Chromium/IndexedDB, two-Worker/Python
Node, deployed page/SW and actual UI send/receive remain separate gates.

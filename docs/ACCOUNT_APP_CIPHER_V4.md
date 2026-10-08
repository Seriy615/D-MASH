# Account application ciphertext V4: narrow integration contract

`account_app_cipher_v4.js` is a confirmed-root consumer for ordinary Account
text. It is inactive until the public Account orchestrator loads it and passes
an authenticated, durable Account history writer into `AccountSessionRuntimeV4`.
Neither `Core` nor a Node receives `confirmed.root` or an application key.

After a genuine public route is ACTIVE and the signed N4 handshake reaches
ESTABLISHED, create the runtime with `App: DmashAccountAppCipherV4` and
`persistAuthenticated: historyWriter.persist.bind(historyWriter)`. The writer
must commit the Account history message and dedupe marker atomically, bind the
peer and operation ID, and reject new messages for deleted or legacy contacts.
It must be idempotent on replay. Inbound managed Inbox may ACK its opaque Node
handle only when `runtime.receive(...)` returns `persisted: true`.

```
await runtime.sendApplication(peer, {
  operationId: '<64 lowercase hex>',
  plaintext: 'Hello',
  contentType: 'text/plain;charset=utf-8'
});
```

The result reports `durable: true, queued: true, recipientAck: false` only
after a locally encrypted application frame has been committed and the Node
accepts its sealed envelope. Node acceptance is not recipient delivery. A
repeat with the same operation ID, plaintext, peer, binding and session reads
the exact saved ciphertext; a changed value fails with
`APP_OPERATION_CONFLICT`. The caller must retain the operation ID and original
text to retry after restart. Automatic unsent-operation enumeration and
authenticated recipient delivery/read receipts are still separate N4 work.

The frame uses a V4 type tag, session ID/generation, signed route binding,
sender/recipient, operation ID and content type as AES-GCM associated data.
Directional AES-256 keys derive from the confirmed root via HKDF-SHA-256 with
the session ID as salt and an application-specific domain. A fresh random
96-bit nonce is generated once, before the encrypted ledger commit. Only
`text/plain;charset=utf-8` up to 8192 bytes is accepted here. Voice/video
bulk bytes remain outside this codec and require their separate S-TURN path.

Inbound processing validates context and AEAD before writing an encrypted
pending operation marker. It then invokes the trusted history writer. A writer
failure prevents Node Inbox ACK; replay after crash calls that writer again.
The encrypted marker is completed only after the writer confirms its durable
commit. Duplicate frames cannot replace an existing operation's ciphertext.
Unknown versioned rows must not be deleted by legacy contact deletion.

`account_app_cipher_v4.test.js` uses WebCrypto and a synthetic transactional
IndexedDB emulator for encryption, exact retry/reopen, tampering, same-ID
collision, callback failure after commit, and abort. This is UNIT evidence
only. Real Chromium/IndexedDB plus two-Worker/Python Node acceptance and
ordinary UI clicks remain required before deployment or a DONE claim.

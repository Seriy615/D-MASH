# Account text pending across a confirmed successor session

This candidate covers an Account text operation that is already encrypted and
durably `PENDING` when an authenticated N4 recovery confirms a new session.
It applies only to the same peer and route binding. It does not create an
offline draft before the first `ESTABLISHED` session.

The sender keeps the stable logical operation ID and local history sequence.
The encrypted outbox holds the original plaintext until a recipient ACK. For
a successor session, Runtime checks the new `ESTABLISHED` state and the old
session ID in the durable retired ledger. Its private proof is bound to the
peer, operation and old/new context. The history writer verifies the proof
and compares all three encrypted SessionStore rows (`binding`, `ledger`,
`state`) inside the same IndexedDB transaction as its history marker CAS.

The ordering is:

1. The writer moves only the outgoing marker context; it checks the existing
   `PENDING` history row and preserves its text, sequence and counter.
2. The outbox CAS moves its encrypted pending intent to the new session. Its
   transport attempt number stays monotonic, so a consumed Inbox packet ID is
   never reused.
3. The AppCipher seals the same plaintext under the confirmed new root, with
   new session metadata in AEAD associated data, then submits it. Crashes at
   any preceding step replay idempotently from the encrypted local records.
4. The recipient authenticates the new frame, checks the same logical ID and
   plaintext through its atomic history writer, updates its inbound ledger,
   and only then sends an authenticated receipt. Different plaintext for an
   existing operation fails closed.
5. The sender's history reaches `DELIVERED` and the outbox drops plaintext
   only after the recipient receipt is authenticated and persisted.

If the prior receipt already made history `DELIVERED` before a crash but the
outbox was not retired, a private writer status proof retires that outbox
intent without another send or context move. A caller-supplied delivery flag
is never sufficient.

This is an inactive isolated candidate. Unit tests cover successor reseal,
same-ID recipient dedupe, three-row proof races, the crash after writer
migration, monotonic transport attempts and the already-delivered crash gap.
The real two-Worker/Python browser fixture and ordinary UI/deployed acceptance
are still required. Binding migration, more than eight successor context
moves, stale old-session Inbox quarantine, and pre-session drafts remain open.

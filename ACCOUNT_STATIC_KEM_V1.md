# Account static Kyber material — inactive integration slice

The explicit profile ACCOUNT_STATIC_LEGACY_KYBER768_V1 creates separate legacy
Kyber768 material for each Account. It does not claim ML-KEM, PCS or fresh-ratchet
PFS. Existing LEGACY_KYBER768_BUNDLE_V1 remains readable; no silent profile fallback
or mixed-profile binding is allowed. Profile choice is covered by Account signature.

`DmashAccountStaticKemV1.open({session})` takes a trusted captured Account session
(db/masterKey/blindSalt/keys.sign/publicKey/generation/rootState/signal/assertCurrent).
It does not create a Core session or confer owner authority. It uses the existing
pairing_material store; no database schema or Core changes are part of this slice.
`load()` never generates keys. `createExplicit()` generates only when the encrypted
Account-scoped row is absent; concurrent creators converge through one IDB readwrite
transaction. Corruption is an error, never a reason to replace existing material.
Reopening uses the same row regardless of login generation. Alias and Account/profile
context are authenticated; encrypted data is tied to a distinct domain with GCM AAD.
The original DeviceRoot/Core legacy Kyber fields are never written by this module.

Caller owns returned public/secret arrays until `release(handle)` or session abort.
At most32 live material handles are retained. Abort closes transactions and clears
tracked secret arrays. Results from stale asynchronous decrypts are zeroed before
rejection. The scoped WASM adapter wipes its heap allocation spans before freeing
memory, including failures. JavaScript immutable parsed strings cannot be explicitly
zeroed; this does not claim protection against a compromised same-origin process.

Precommit run6978 (exit0), two codec/unit scripts and actual WASM/IndexedDB browser
test PASS. The browser covers separate Accounts
sharing the same root context, concurrent creation, reopen equality, release/abort,
stale decrypt and failed generation wiping, corruption refusal, real encapsulation/
decapsulation and unchanged separate legacy key fixture. Session guards in this
mechanism fixture are synthetic; genuine Core capture/ordinary UI remains required.
Public Worker/Python browser variant uses real persisted per-Account KEM public keys
instead of parser fixture bytes; its network acceptance is a separate pending gate.
No final Account journal/ACTIVE/session status is minted by this module.

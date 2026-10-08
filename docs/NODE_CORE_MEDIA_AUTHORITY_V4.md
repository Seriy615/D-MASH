# Candidate Core authority boundary (not deployed)

Base: PRIVATE product 279e3cd/harness b386742, with the ordered N4 CONTROL,
successor, asynchronous receipt and expired-replay commits through 922c51f,
and service-only candidate 56d453b. Page/SW remain review `.34`; root must
choose a new release identity before publication. No production or user state
was accessed. This is an integration candidate, not N3/N7 acceptance.

Core provides:
- `canQueueNodeMediaV4(peer)`: read-only decrypted Node contact membership,
  unlocked/no security alert; local encrypted file intent only, never wire authority.
- `confirmedNodeMediaPeerV4(peer)`: opaque current Account/Host ACTIVE/N4
  ESTABLISHED capability. Peer need not be online. Deleted/locked contacts fail.
- `selectNodeMediaServiceV4({peer,authority,file})`: same-channel signed pinned
  Node service selection, returning a branded frozen `{endpoint,wssEndpoint,nodeId}`.
  Use `.endpoint` for WSS, pass the exact object to send; no v3 STATUS fallback.
- `sendNodeMediaControlV4({peer,authority,message,service,record,operationId})`:
  exact typed bridge then durable N4 enqueue. Local enqueue is not delivery.
- `verifyNodeMediaControlV4(authority,{peer,message,phase,taskToken})`: private
  incoming brand, full post-bridge envelope, live Account/contact/owner/session,
  and fresh encrypted dispatcher row. Default `start` requires invite freshness.
- `beginNodeFileTransferV4(authority,{peer,transferId,transportId,sha256,size})`:
  atomic encrypted dispatcher CAS writes APPLIED and accepted task together;
  returns opaque task token. Deadline is exactly one hour from the first start,
  never extended by duplicate/reload. `commit` verification requires this token,
  exact APPLIED task and unexpired task deadline, not invitation freshness.
- `drainNodeMediaControlsV4()`: accepts no caller rows. Rehydrates private
  incoming capabilities only from durable authenticated dispatcher records.

The trusted FileRuntime must declare `nodeControlAuthorityV4 === true`, accept
`{controlMode:'node-v4',authority,resuming,taskToken}`, and perform fresh Core
verification before side effects. Fresh tasks call `begin` before network work;
recovered APPLIED tasks use commit verification and their original immutable
manifest/deadline. Return `{accepted:true}` only after durable task/outcome intent.
FileVault remains responsible for hash/size verified bytes and semantic outcome
persistence. Existing APPLIED tasks may be offered idempotently until deadline;
FileRuntime must not recreate an already completed file. Receiver outcome
retention is not implemented by this task journal.

Same-origin dependency wiring is trusted code, not a sandbox against arbitrary
same-origin JavaScript. Public objects/booleans cannot forge WeakMap brands.
Service TTL/health failure and rekey without verified dispatcher successor fail
closed. No Account secrets go into Node service queries or transit.

Targeted synthetic tests cover opaque brands, forged/cross-context records,
Account/rekey revocation, atomic APPLIED+task concurrency/reopen, expired ACK
reconciliation and unchanged deadline. Browser PRIVATE, actual signed service,
N4 CONTROL transport and ordinary S-TURN file/call/voice acceptance remain NOT RUN
for this tree. The coordinator currently dispatches file controls only; call and
recorded media consumers remain separate implementation gates. UI media controls
remain fail-closed until the corresponding runtime is integrated and tested.

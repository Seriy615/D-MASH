# Core IPC contract for client model adapters

The client presentation layer talks to the resident credential/Account owner;
that owner talks to the separate Node daemon. This boundary does not depend on
Qt Widgets, Java Views or a particular frontend. A Telegram-derived client must
adapt its models/actions to these actual domain DTOs rather than forward its
original server protocol or obtain Account keys from Node.

## Connection and authority

Use the existing private credential-host locator/session handoff and four-byte
big-endian length-prefixed UTF-8 JSON frames. Keep requests scoped to the owning
profile and use the existing same-user/session authentication. No credentials,
capabilities or keys belong in URL/query strings, process arguments or logs.

Request: `{v:1,id:string,method:string,params:object}`. Response:
`{v:1,id:string,ok:boolean,code:string,result:{value:object,rows:array}}`.
Correlate by `id`; an EOF or timeout is not a negative durability ACK. Reconnect
to the same owning profile and reconcile model state before retrying uncertain
mutations. Never reset an accepted vault or manufacture a new Root/Account to
recover a client connection.

Root unlock, Account login/logout and Node lifecycle are distinct. Node may run
with zero Accounts or after Account logout. Root lock revokes/stops its scoped
Node transport. The UI must reflect returned state, not infer that binding a
service or closing a window enabled/stopped Node.

## Contact model

`account.contacts` returns `rows` with `id,name,state,chatLocked`. A 64-hex `id`
with `state:'NODE_ACCOUNT_V4'` is an authenticated Node Account contact. Saved
Messages uses the existing local identifier; preserve it as a local chat.
Legacy/security-alert/locked contacts require their existing supported flow;
do not relabel them as ready Node contacts.

Use [private pairing](PRIVATE_PAIRING_API.md) for actual create, inspect,
request, explicit selection/deny and signed commit/activation. UI rows are
backed by `account.pairingOffers`; signed canonical bundles are data. Do not
create model contacts by injecting routes, skipping journal receipts or marking
an inspected offer as already accepted. Public intake is a separate lifecycle
and is not yet exposed by this native private facade.

## Message model and send action

The client generates one random 64-lowercase-hex `operationId` for a logical
send. Call `account.sendText` with `{peer,operationId,text}`. Keep that ID and
exact text across a lost local RPC reply; a conflicting text with the same ID
must be rejected. A new user message receives a new ID.

The pending-send extension (`562941a`, author actual candidate01 PASS7158)
returns `value:{accepted:true,operationId,transportState,recipientAck}` only
after Account durability. Its states mean:

| State | Meaning |
| --- | --- |
| `HANDSHAKE_PENDING` | Encrypted first-send intent is durable in the Account vault; E2EE has not established. Ordinary sync automatically hands it to the established-session outbox later. |
| `APPLICATION_PENDING` | Account intent/outbox is durable; this is not a Node custody or recipient delivery ACK. |
| `NODE_ACCEPTED` | Existing older facade result: actual local Node accepted its durable job; no recipient ACK is implied. Clients must continue to understand retained responses. |
| `DELIVERED` | Only authenticated Account delivery evidence may produce this state; never infer it from a local write, timeout or packet send. |
| `LOCAL` | Saved Messages was committed locally. |

Clear the composer on `accepted:true`; retain the local operation/text if the
RPC outcome is unknown. Do not ask the user to retype a durable pending message.
Do not automatically mint another operation ID on a transport timeout. The
first-send queue and established outbox own automatic flush/retries, not the UI.

`account.history{peer,before?:number,limit?:number}` returns rows with
`sequence,operationId,direction,text,time,state`; `direction` is `in` or `out`,
`time` is Unix milliseconds. Use `operationId` for optimistic-row reconciliation
and deduplication. A durable pre-handshake pending row has `sequence:0` and
`state:'HANDSHAKE_PENDING'`. Zero is not a server message ID or pagination
cursor. It becomes the same logical outgoing row in ordinary authenticated
history after outbox handoff, rather than an additional message. Positive
`sequence` values remain the existing local history cursors. Pending rows appear
on the newest page (`before` omitted/zero); older pages retain positive cursors.

A pending row is private Account data. Model caches, crash reports and telemetry
must not send its plaintext to Node or the mesh. Preserve the existing encrypted
Account database/history rather than maintaining a parallel unencrypted queue.

## Progress, cancellation and recovery

Call `account.sync` while the Account model is active. Its `rows` contain
`{peer,consumed,status}` on success or `{peer,code}` for a deferred/failed peer.
Read `status.phase`; local route activation alone does not mean E2EE is ready.
The Account runtime also resumes its established peer work on its normal retry
cadence. A client refresh must not create new pairing requests or repeat logical
sends with new IDs.

On Account logout/cancel, fence callbacks from the old session and clear its
plaintext model. Do not stop autonomous Node merely because Account UI closes.
After owner restart, unlock/log in through the same owning profile, refresh
contacts/history and resume sync. The pending first-send extension retains its
operation IDs through Account logout and actual host crash. Account history
commits precede Inbox consumption; the existing dedupe handles replay after a
crash between those commits. None of this adds a mesh custody ACK.

## Acceptance boundaries

- Immutable private-pairing candidate03 proves actual signed bilateral pairing,
  concurrent activation, real Kyber/E2EE and history reopen through configured
  native Nodes/Python transit. Its old first-send caller retry is historical.
- Pending-send candidate01 author actual PASS7158 uses a new Account binary
  and unchanged Node: durable first send before remote readiness, Account
  logout and actual owner crash/reopen, automatic bilateral delivery/history2
  and no caller retry. Root independent acceptance remains separate. Unit
  crypto/IDB checks alone do not constitute network acceptance.
- Browser/native mixed pairing, public intake, ordinary Telegram client actions,
  NAT/self-organization and deployed behavior require their own actual gates.

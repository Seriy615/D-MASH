# Resident credential owner

`dmash-credential-host --profile DIRECTORY --node-host BINARY` owns the broker,
Account workers and the separate Node child's bootstrap lifetime. Root/PIN,
Account E2EE keys and legacy Kyber remain in this owner process. The development
profile key is an app-private random file; this is not an OS-vault claim.

The UI connects to the ready locator `DIRECTORY/credential-endpoint.json`:
`{"v":1,"endpoint":"..."}`. It may start a detached owner if no live endpoint
responds; the profile lock makes competing starts converge. Closing the UI only
closes its local connection. Existing accepted stores with a missing profile key
refuse recovery rather than creating another installation.

Local framing is unsigned 4-byte big endian byte length followed by UTF-8 JSON,
maximum 64MiB. Requests are `{v:1,id,method,params}` and responses
`{v:1,id,ok,code,result:{value:{...},rows:[...]}}`. Import's complete package must
fit the broker's existing 64MiB bound. No raw Root/material export method exists.
The local endpoint permits only the same OS user. Inputs contain user-entered
Root PIN/Account password only over this private owner channel, never argv.

Methods: `host.status`, `profile.import {profile,pin}`, `root.unlock {pin}`,
`root.lock`, `account.listAccounts`, `account.login {identity,password}`,
`account.contacts`, `account.history {peer,before,limit}`,
`account.sendText {peer,operationId,text}`, `account.logout`, `account.cancel`,
`node.enable {endpoints:[{url,nodeId}],directEnabled}`.
Import/unlock performs the broker's Account publication gate internally before
returning authenticated Account registry rows. `account.cancel` fences current
work immediately; accepted durable writes retain their real outcome.

Explicit first Node enable provisions only missing independent Node slots behind
the same Root with revision CAS. Mining derives Ed25519 public keys natively and
uses the exact existing bundled BLAKE3 JavaScript over UTF-8 lowercase publichex,
requiring prefix `0520`. Existing valid slots are reused; authenticated malformed
or invalid-proof slots refuse replacement. Node storage stays separately derived
from Root; Account keys/DeviceID are not used as Node identity material.

`host.status.value` includes `rootLocked`, `profileExists`,
`accountSessionActive`, public `account` display fields, `accountImportPhase`,
`nodeRunning`, `nodeState`, and accepted `nodePolicy`. Import/unlock returns
Account inventory in `result.rows`; Account methods preserve the facade's
`result.value`/`result.rows` shape. `node.disable` currently performs a full Root
lock and Account cancellation before confirming the owned Node has stopped;
it returns `rootLocked:true`. Reopening requires Root unlock. Endpoint policy
is retained as private public-config JSON, without capabilities or secrets.

Linux process tests cover the actual private IPC and separate Node executable,
UI detach/reconnect, Account logout, Root lock, clean restart, accepted missing
Account database and missing development-key refusal. This is not remote-chat
or visible UI acceptance. Windows bootstrap helper has crosscompile evidence;
actual Windows host execution and Android service integration are separate.
Owner capabilities retain their bounded lifetime (one hour for Account owner,
one day for broker). The resident owner renews both over its private bootstrap
lease every thirty minutes, with bounded five-second retries after failure.
Rotation serializes with new route authentication and retains existing owner
connections/grants. `node.renew` exercises the same renewal immediately; the
process gate checks actual capability rotation, a new owner connection and the
existing broker connection. Android supervisor adapters implement the additive
`renewCapabilities()` hook on their retained bootstrap FD. Crash recovery after an unclean host/daemon exit must reconcile existing
durable floors before another session; it must not reset the Node profile.

Account cancellation fences/logs out only Account work and preserves the unlocked
Root and installed Node. Cancelling pending profile import, Root unlock or Node
provisioning performs the full Root/owned-child stop path before returning locked
status. Pending replies are fenced too, so an already computed login result
cannot publish a stale successful session after cancellation. The actual process
gate pipelines login/cancel with Node enabled and retries login without another
Root unlock; it separately pipelines Root unlock/cancel and checks stopped state.

# Credential IPC Account binding

Status: **implemented; independent process IPC and worker PASS**. Actual fork
frontend integration and visible UI acceptance remain open. See
[root evidence](../../docs/native/2026-10-20/root-account-client-binding.json).

Implementation contract for the confirmed multi-window selected-Account fault.
This extends local credential IPC only; mesh frames and Root/Node APIs do not
change. Account keys remain in the Account service.

Each credential IPC connection starts without an Account binding. A successful
`account.login` binds only its requesting connection to the authoritative
`accountPublicId` and `sessionEpoch` returned by the Account worker. Selecting
another Account, logout, Account cancel or Root lock invalidates the old epoch.
The epoch distinguishes logging out and back into the same Account too.

A new or reconnected client that intends to resume an already selected Account
must call `account.attach` with `{accountPublicId: '<expected 64-hex key>'}`.
The worker binds only if that exact Account is still active and current. The
result returns authoritative public Account details and `sessionEpoch`.
Inspecting `host.status` is not attachment. Clients must not attach to a newly
observed different Account without explicit user selection.

Contacts, history, sendText, sync, pairing and logout require this connection
binding. Their validation runs inside the Account worker immediately before the
original operation. The worker checks both expected Account and epoch, and
fences returned rows/values if the session changes while work runs. Unbound
requests return `ACCOUNT_CONTEXT_REQUIRED`; stale/mismatched contexts return
`ACCOUNT_SESSION_CHANGED`. Clients clear old Account presentation and retain an
uncertain send's operation ID for same-Account reconciliation; they must not
retry the send under another Account.

`account.cancel` may cancel only this same connection's pending login/create
(or its own pending Root setup operation), preserving bounded cancellation of
password derivation. Otherwise it requires the bound active Account and follows
the same worker validation as logout. It cannot cancel another window's pending
selection. Root lock and Node controls remain explicit Root-neutral operations.
Account inventory and creation do not read or mutate the selected Account's
history and remain Root-neutral.

Internal trusted C++ AccountService callers retain their existing APIs. The
credential IPC dispatch routes all selected-Account operations through the new
bound worker entry; it does not silently accept older unbound secret RPCs.
Frontend adapters use their existing persistent socket. Reconnect attachment is
an explicit expected-Account operation, not a global expectedAccount field on
all RPCs and not a network protocol change.

Acceptance requires two independent UI connections, two synthetic Accounts,
retained Saved histories, old-window reads/writes/logout/cancel rejection after
switch, exact same-Account reattachment, same-Account relogin epoch rejection,
and queued worker race fencing. No actual frontend UI acceptance is implied by
the component IPC test.

# N3 Account / local Node cutover — design delta

Status: **PROPOSED, NOT IMPLEMENTED**. Review checkpoint: 8 October 2026,
source `2ee3be9fe05e7844480a194e92b11b18c5e2c04d`. This document specifies
next implementation boundaries, not completion of N3 or N0–N8/A–M/E6.
N4 authenticated recovery/transcript state machine is a separate next contract.

## Verified gaps

- Ordinary root unlock/bootstrap never starts `NodeRuntimeHostV4`; Core attachment
  is opt-in. `_ensureAutomaticMeshRoute` still installs `PrivateRoutesV3`.
- Core transport dispatch falls back to NodeManager when no v4 adapter is attached.
  That behavior cannot remain the default in a v4-selected session.
- v4 local Inbox maps established local routes to known Account peers. It does
  not provide the Account-neutral public-contact dispatcher required before login.
- Worker host exposes bind/submit/inbox, but no authenticated route retirement,
  old-owner migration or universal durable network store/drain contract.
- Native v4 routing queues are in-memory. Existing directional relationships and
  encrypted browser Inbox do not implement universal offline next-hop mailbox.
- Existing directory is same-origin `nodes.json`, fetched with `no-store`; there
  is no directory signature verification. `NodeManager.requestNode()` copies
  only selected URL/label/public/autoConnect, discarding any catalog NodeID and
  capabilities. QR/manual canonical descriptors can retain a NodeID, but this is
  not a pin for an automatically requested public Node. Do not describe current
  directory loading as independently authenticated signed discovery.
  A subsequent working-tree catalog patch provisions the EMS public NodeID
  independently obtained over authenticated SSH; selection preservation remains
  part of the separately owned NodeManager/UI fix. This is a v3 catalog repair,
  not activation of the proposed v4 descriptor.

## Bootstrap and descriptor ownership

Create one module owning root-session host lifecycle and neighbor selection.
It imports no Account engine. Its API supplies `getHost`, captured session
version, cancellation and visible readiness/error state. Root unlock starts the
Node worker; saved explicitly enabled neighbors reconnect. Selecting an Account
attaches that Account's guarded consumer/transport. Logout detaches its keys and
consumer while preserving unlocked Node transit, owned routes and pending Inbox.
Root lock aborts mining/work, closes sockets and terminates the Worker. Existing
exclusive cross-tab ownership remains mandatory; losing tab reports unavailable.
No Account switch changes NodeID. No reset, new root or Account signing-key reuse.

Canonical v4 descriptor must validate protocol version, pinned NodeID, explicit
mesh WSS URL, capabilities and admission policy. The public catalog must carry
an operator-provisioned NodeID, verified independently against the deployed Node
before publication, and preserve it through selection/persistence/reconnect.
Same-origin HTTPS distribution trusts the application publisher/TLS; it is not
a signature-backed decentralised directory. A future signed directory needs an
explicit trusted verification key/rotation contract. Until a valid independent
pin is provisioned, fail closed instead of learning identity from the connecting
socket. Existing QR pins retain their stated out-of-band trust boundary.
Do not mechanically replace `/dmp-c/v3` with `/mesh/v4` and trust the resulting
endpoint. Password admission and resource grants still apply to all NODE peers.

A selected v4 mode must never call DeviceClientV3 after failure. Retained v3
records/readers are an explicitly labelled migration facility, with removal gate
and no automatic downgrade. Unavailable v4 transport remains unavailable visibly.

## Account routes and public contacts

A versioned private pairing exchange binds Account identity, contribution,
protocol/suite and certified route information with Account authentication.
Use independent domain-separated route authority, discovery and recipient keys;
never make the Account signing key the Node identity or transit secret.
Verify route certificates against the authenticated pairing bundle, not just
self-consistency of an arbitrary supplied certificate. Define renewal/generation
and expiry; stale final/old pairing cannot overwrite a newer active mapping.

Persist transaction/recovery markers for prepare → local binding → authenticated
peer mapping → active transport. Outbound peer certificate and inbound route/peer
mapping must recover coherently after a crash. Guards capture Account generation
before awaits; late completion cannot write another vault. Keep legacy peer,
identity/history and ciphertext records intact. Legacy pairing lacking v4 evidence
must show upgrade/migration required rather than fabricate trusted metadata.

Public contact route ownership belongs to the unlocked local Node, independent
of selected Account. A local dispatcher unwraps its recipient envelope into a
bounded, encrypted neutral request record, keyed by a blind request handle.
Transit never receives Account keys or plaintext. Public membership grants no
right to overwrite route/mailbox ownership. Request/Accept/Confirm use signed
Account bundles after explicit local Account selection, durable attempt IDs and
retries; peer confirmation, not Node acceptance, establishes contact. UI navigation
must actually permit inspecting and accepting while the chosen Account is open.
Locked/unselected Accounts retain encrypted pending records without implicit login.
End-to-end messages and receipts remain opaque normal Node queue payloads.

## Universal mailbox and authenticated migration

Specify store grants separately from NODE membership and route advertisement.
A durable owner is the authenticated recipient Node plus verified directional
relationship/grant. Blind aliases use keyed domain-separated derivation; raw
AccountID and DNSS are not persistent lookup keys. Grant expiry, revoke, quotas,
concurrent arrivals, replay, fresh reconnect binding and restart are explicit.
The same queue operation serves temporarily offline transit and local delivery;
no endpoint-only operation or terminal receipt enters the wire protocol.

Drain returns ALL authorized rows in a quota-bounded snapshot: lease, await send,
delete only successfully sent leased rows. Failure releases lease and retains
ciphertext. Arrivals outside the snapshot remain queued. Server crash between
send/delete can duplicate; send before client persist can lose data. Account
stable IDs/retries/receipts cover this documented boundary. Do not add mandatory
client ACK silently.

Migration requires proof of both old authenticated owner and new Node owner,
a fresh session-bound transcript, a versioned idempotent transfer identifier and
replay-resistant durable progress. Preserve old ciphertext until destination
ownership/readability and correct Account dispatch are verified. A mixed-version
peer receives an explicit migration/upgrade outcome, never a hidden fallback.

## Stages, backup and rollback prerequisites

1. Inventory protected roots/identities, Account vault/history, old route/mailbox
   state and matching encryption keys; capture consistent encrypted DB backups
   including WAL semantics. Git checkout is not a runtime backup.
2. Provision independent v4 descriptor pins and root-host lifecycle, without
   switching existing Accounts or deleting legacy state.
3. Prepare versioned bindings/mappings and migration records, verify proof and
   durable write ordering; old readable data remains authoritative until commit.
4. Verify destination Node ownership, local Inbox and Account decrypt/persist;
   mark individual migration committed, then select v4 transport explicitly.
5. Test restart at every transition and rollback read compatibility. Only retire
   old ciphertext/readers after authenticated recovery and retention criteria.

Before any deploy, the selected build must read existing encrypted storage and
rollback must read both pre-migration and committed data or use the separately
verified protected restore procedure. An incompatible downgrade must refuse
cleanly. Never delete storage to make startup or tests pass.

## Ownership and acceptance gates

Bootstrap module/descriptor lifecycle: Node agent. Account certificate/pairing,
Core adapter, guarded mapping and public bootstrap: Account agent. Reachable UI
navigation, migration/readiness/errors and visible Request/Accept/Confirm: UI
agent. Universal mailbox/backend owner migration is a distinct implementation
slice with coordinated wire fixtures. The lead integrates and independently tests.

Required evidence before N3 acceptance:

- Actual ordinary UI root unlock → Node Worker → native EMS → Worker → Account,
  two real profiles, private and public contacts, messages/receipts both ways.
  Observe wire role/protocol and assert no v3 sockets/fallback for v4 mode.
- Account A active while B receives, B later unlocks; public request without login;
  logout preserves genuine foreign transit, root lock closes it. Multiple tabs,
  reload/reconnect and identity equality across lifecycle.
- Missing/wrong pin, version, password, ownership, expiry, replay and unavailable
  route; visible error/loading/disabled/cancel states. No silent downgrade.
- Existing identities/root/history preserved through authenticated migration;
  crash/restart per stage, wrong old/new owner, stale proof, duplicated transfer,
  encrypted old mailbox retention, recovery and rollback readability.
- Store ALL/lease/send/delete, failed send/release, concurrent arrivals, server
  crash, bounded client retry and invalid-first Inbox record isolation.
- Exact integrated commit tests and published source/page/active SW checks;
  independent UI clicks and real transport after deploy. Unit or programmatic
  host fixture alone cannot pass ordinary UI acceptance.

Fresh baseline evidence in `docs/evidence/2026-10-08/qa-node-*` proves only its
listed Worker transit/ownership/Inbox/deployed pinned-auth slices. It does not
implement this design, close N4, or establish anonymity/PFS/PCS/PQ/full DONE.

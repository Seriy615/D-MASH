# N7 file transfer contract (candidate)

This document describes the candidate file path for confirmed contacts. It is
not a claim that N7 or ordinary Node contact integration is complete.
The user's later, explicit policy supersedes the older per-file-consent wording
in Plan section 11: an authenticated, confirmed peer's file is received
automatically within the size and retained-byte quotas, without a per-file
Accept prompt. Rejection and limit errors remain visible, and the sender must
  retain control to cancel an outstanding local transfer. A cancellation stops
  the local S-TURN session and persists CANCELLED with encrypted bytes retained;
  a later authenticated receiver commit may still correct the status to
  DELIVERED if the two events crossed in flight.

## Authority and wire path

- Only an authenticated, confirmed Account peer may trigger automatic receive.
  The current adapter proves this with the existing v3 contact secret. Ordinary
  Node v4 contacts need their own authenticated control adapter before this
  feature can be enabled for them. A missing v4 adapter must fail closed; it
  must not silently choose v3.
- FileVault metadata and the Account-owned inventory carry an authenticated
  `controlMode` (`v3-private` or `node-v4`). Existing sealed v1 rows without
  this field are interpreted only as `v3-private`; Account transport changes
  never upgrade them implicitly. A new write must state its mode, and an
  inventory/metadata disagreement blocks reads, updates and deletion.
- The ordinary Node adapter must obtain a current opaque confirmed-peer
  authority from `Core.confirmedNodeMediaPeerV4(peer)`, select a signed
  same-channel S-TURN service through `Core.selectNodeMediaServiceV4`, and
  persist typed encrypted CONTROL through `Core.sendNodeMediaControlV4`.
  Local offline attachment is a separate decision:
  `Core.canQueueNodeMediaV4(peer)` checks the Account-owned confirmed Node
  contact before FileVault stores a `node-v4` WAITING row. It grants no right
  to submit a network control.
  Incoming effects must first pass `Core.verifyNodeMediaControlV4` against
  a private, durable N4 dispatcher row. No raw message, staticShared secret,
  or legacy service selection is accepted as Node authority. These Core
  seams and the real ordinary-Node browser gate remain separate work.
- A Node INVITE is accepted only after `Core.beginNodeFileTransferV4` atomically
  records the authenticated APPLIED control and exact accepted transfer task.
  An in-progress transfer can finish after the INVITE expires only while fresh
  private `phase:'commit'` verification finds the same task within its original
  one-hour deadline. A cancelled or completed accepted task leaves a bounded
  encrypted terminal outcome marker for replay suppression; pending semantic
  COMMIT_ACK/DECLINE controls keep the same persisted operation ID and
  five-minute `expiresAt` across uncertain enqueue retries. Only after that
  deadline does one Account-encrypted journal CAS rotate both fields under the
  same logical file/hash/reason; an expired control is never reported durable.
  The marker never authorizes a new transfer start.
- voip_file_request is an Account end-to-end encrypted typed control payload.
  Version 2 adds a stable random file_id distinct from the per-attempt
  S-TURN session_id. The request retains expires_at, signaling,
  encrypted_metadata, size_bytes, chunk_bytes, sha256, and resumable:false.
  File bytes never enter the Node message envelope.
- Authenticated completion/rejection controls carry file_id and sha256
  (rejection additionally has a bounded reason). FileSession carries bytes
  only through the selected EMS S-TURN service and verifies the manifest hash.
- If a receiver is already handling a file, it sends an authenticated
  RECEIVER_BUSY rejection bound to file_id, sha256 and that attempt's session_id.
  The sender retains its encrypted file in WAITING and retries with a new
  S-TURN session after bounded backoff. A late BUSY from an older session
  cannot stop a newer attempt; permanent storage/decline errors remain distinct.

## Local durability and privacy

- Before any network invitation, the sender commits encrypted file bytes,
  authenticated Account/peer ownership metadata, an inventory entry, and a
  local file_ref chat message marked WAITING. Offline retries reuse file_id;
  a new S-TURN session may be negotiated for each attempt.
- The receiver commits encrypted file bytes and a local file_ref message
  before FileChannel sends its final acknowledgement. A repeated authenticated
  request repairs a missing chat card and does not duplicate a committed file.
- The shared Gamma vault has blind_files and blind_file_owners. Its owner
  inventory is AES-GCM authenticated to the 64-hex Account signing identity,
  and every file alias binds Account, peer, and file_id. File bytes are
  separately encrypted in bounded chunks with AES-GCM associated data binding
  their alias, size, hash and chunk index. A second Account cannot enumerate
  the first Account's inventory. Chat deletion uses authenticated peer proof
  and an owner-revision check; it never clears the shared database.
- Image, video, and audio previews use local decrypted object URLs inside the
  chat. Other files show a local card and explicit save control. No file is
  written to the OS without a user click. Size and storage quota failure must
  remain visible, and the sender's encrypted bytes stay local for inspection.

## Acceptance still required

Real Chromium/IndexedDB owner isolation, forced EMS S-TURN two-profile UI
auto-receive, file hash, previews and generic save clicks, reload/offline
status, quota failure, exact page/SW version, and ordinary Node v4 control
authority are separate gates. UNIT results alone do not close them.

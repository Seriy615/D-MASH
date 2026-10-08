# Ordinary Node candidate on .35 — not deployed

Base `74162704f55fd1671a42578410b9e409425efdaa` (product
`6a01feb252c1b94772a2b19503c9e1576a8c6356`). Isolated worktree:
`/tmp/dmash-node-ordinary35-integration`.

Composition:
1. Merge frozen `965889a`: ordinary .34 Node dependency integration, root
   lifecycle22994, owner-safe contact migration6bf, private owner563,
   receipt continuation4262, PRIVATE UI279e/harnessb386, Core/media authority.
2. Cherry-pick `5eed0d3`: persist ACTIVE epoch and reconcile crash-before-detach.
3. Merge authoritative N4 `247fd32`, retaining crypto/outbox/runtime exact;
   this includes bounded routing reprobes02b5007 and owner cancellation3295634,
   CONTROL successor, async durable receipts and expired APPLIED replay.

Conflicts resolved deliberately:
- release.js: `.35` retained, FileVault loader retained, Node dependencies union.
- N4 add/add bridge/dispatcher: retained Core authority/task additions965889a,
  whose underlying crypto/expired behavior matches latest N4.
- Python/JS routing constructors/removal: retain BOTH service query cleanup and
  discovery rate tracking/cleanup; never choose one whole side.
- CONTROL crypto test: latest N4 cross-module expired restart regression.

The `.35` FileVault/FileRuntime/FileChannel/FileSession, recorded notes, Storage
and call sources are byte-identical to the product base. Core changes compose
with .35 Account deletion and captured-file-preview guards. Page/SW stay `.35`
for source review ONLY; root must assign a new release before any publication.

Controlled opt-in: set `window.DMASH_NODE_PROFILE='managed-v4'` BEFORE release.js
on synthetic source-overlay profiles. Default remains `legacy-migration`.
Root auto-start, new Node contact UI and Core Node adapter require the opt-in.
Existing NODE_ACCOUNT_V4 contact guards still prohibit legacy crypto/media/send
fallback when opt-in is disabled. No preference or identity is rewritten.
`qa_node_private_ui.cjs` sets the explicit opt-in and records it, immutable source
manifest/response hashes, and protected off-Git state backups. SW is blocked in
that fixture; it is not deployed/SW-upgrade evidence.

Full candidate UNIT suite is run after the source checkpoint. Required browser
and deployment gates are NOT RUN on this composition: root-only foreign transit,
PRIVATE ordinary two-party pairing/text, retained Account/logout/reload,
existing V3 contact authenticated migration, real service descriptor channel,
CONTROL S-TURN file/voice/circle/call and expiry/recovery. The Node FileRuntime
adapter is a separate QA-owner candidate; current file consumer capability gate
refuses the legacy runtime. Call/recorded media consumers remain open. No N3/N7
or overall N0–N8 completion claim follows from compilation or UNIT PASS.

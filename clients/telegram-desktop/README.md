# D-MASH client using the actual Telegram Desktop fork

The explicit user requirement is the actual Telegram client UI. The previous own Qt Widgets imitation is preserved as historical implementation/evidence; it is not the selected frontend. This recipe pins the original Telegram Desktop repository and records reviewable changes without copying the entire dependency tree into the MIT core repository.

Upstream revision and license/submodule inventory are in `UPSTREAM.json`. Run `scripts/checkout.sh` to create the isolated source checkout. Telegram sources, assets and derived client changes keep GPL terms and upstream notices. The D-MASH Node and credential/Account processes remain separate and communicate through the existing local framed API. No Telegram network account, SMS login or MTProto fallback is part of D-MASH.

The integration keeps the real Telegram navigation, dialogs, history renderer, composer, controls and assets. Root/Account authentication replaces Telegram authentication. Native encrypted Account storage is authoritative; Telegram presentation models are populated in memory only while logged in and cleared on logout/Root lock. Numeric peer/message IDs are local presentation identifiers with collision checks; Account public keys, operation IDs, network routes and cryptography stay unchanged. The client uses a D-MASH app-data namespace and must never open an installed Telegram `tdata` directory.

Current source checkpoint includes the original Intro Step with original Telegram
input widgets/styles for native unlock/login; Main::Account session projection;
original Data::Session contacts and History messages; and the original primary
composer calling account.sendText with a stable operation ID. The composer clears
only after accepted:true, and pending operation/sequence-zero rows use stable local indices converted by
the actual upstream ClientMsgByIndex function into its reserved client-ID range. Account logout/Root lock clears RAM presentation while Node
lifetime stays owned by the resident native host. This wiring is a draft and has
NOT passed full application compilation or real UI acceptance. Fresh setup,
imports, paging, all alternate send paths, media/calls, full persistence fencing
and process/network acceptance still require implementation and tests. Do not run
this draft against personal Telegram or D-MASH data.

The standalone Qt6.12 IPC/SessionAdapter/production HistoryProjection library
compiled (11 build steps). Its projection CTest passed 1/1 in 0.01s: stable
operation ID from pending sequence-zero to final sequence, no duplicate, oldest
first, distinct peers and no invented recipient acknowledgement. The test selects
unchanged public MsgId/ClientMsgByIndex definitions from the pinned upstream
header to check the real reserved range; it does not compile the complete app
PCH/schema. Production uses the complete original header. Simple negative IDs
such as -1 are **outside** Telegram's actual client-message range.

The full original app configured successfully with Qt6.12 private module targets,
Ada/Boost/FFmpeg/OpenAL/rnnoise/tde2e. Actual upstream tg_owt build-tree exports
are available; its archives still need compilation before linking. Original UI
libraries/codegen/PCH and ModelBridge/Intro/HistoryWidget objects are now building
from the actual Telegram target. No full fork binary or rendered UI is claimed.
The optional upstream-widget bootstrap target remains a diagnostic, never the
selected messenger. Upstream media/call implementation remains intact.

Account auth/self/settings/draft Telegram persistence is bypassed in D-MASH mode;
the remaining storage/media audit is open. The RAM session invalidates on idle
host disconnect and tracks account epochs. A periodic identity check supplements
this. The host enforces connection-bound Account identity and worker epoch;
login binds the same persistent socket. The adapter never activates an Account
from inventory/status alone. Explicit `attach(expectedAccount)` can bind only
that selected Account, and typed context errors clear the old RAM projection.
Deferred history/callbacks retain their local selection epoch. The component
regression covers inventory, exact/mismatched attachment, stale history and idle
disconnect; actual full-window two-client acceptance remains NOT RUN. Draft text/operation IDs remain when a send RPC reports an
error without session loss; preserving an unsent draft across host/session loss
requires an Account-owned encrypted draft API and is not implemented.

`scripts/checkout.sh` reads the pinned revision, license, recursive gitlink map,
patch digests and final patched-file hashes from UPSTREAM.json. It refuses
unexpected existing changes before submodule mutation and never resets or cleans
a checkout. Upstream automatic updates and crash reporting are disabled explicitly
in the actual app configure script. License classification is in LICENSES.md.

For Linux dependency preparation, `LINUX_DEPENDENCIES.json` pins the downloaded
Ubuntu package versions and file digests. `scripts/prepare-packages.py` downloads
and extracts them into the owned cache without installing system packages.
`SOURCE_DEPENDENCIES.json` records the exact Ada, rnnoise, tde2e and tg_owt upstream
revisions, recursive submodule heads and license-file digests.
`scripts/prepare-source-dependencies.py` builds them sequentially with one worker.
The package/dependency list is still being completed against the full app; it is
not a claim that a clean-machine full application build already passed.

After configuration, `scripts/build-linux.sh` builds the selected `Telegram`
application target with one worker. It sets the owned GIR, Python and pkg-config
paths needed by the original Linux integration generators. Explicit Ninja object
targets may be supplied for a compile checkpoint; that is not a linked application
or UI acceptance. Earlier attempts failed first at missing GIR search path and
then literal pkg-config lookup; both failed logs are retained locally. The owned
environment correction passed these generators in the next incremental build.

The new `Actual Telegram Desktop Linux fork` workflow builds the full original
application on an ephemeral Ubuntu24 runner with exact Qt6.12/owned dependency
pins, then the matching separate credential host and Node binaries. Only external
dependency outputs are cached and verified; project source/build/tests are not
cached. A successful build produces an Ubuntu24 developer bundle with dynamic
runtime dependencies, upstream/core/dependency notices and per-file hashes.
The startup probe captures the real full-fork process's X11 window. It is explicitly
Intro-render acceptance only; Root/Account/Saved clicks, Node transit and lifetime
are not inferred. Build failures keep their logs and source/cache metadata.
This workflow and full clean-run package/smoke path have NOT RUN yet; local checks
so far are Python/shell/YAML parsing and exact dependency-source verification.

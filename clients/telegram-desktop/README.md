# D-MASH client using the actual Telegram Desktop fork

The explicit user requirement is the actual Telegram client UI. The previous own Qt Widgets imitation is preserved as historical implementation/evidence; it is not the selected frontend. This recipe pins the original Telegram Desktop repository and records reviewable changes without copying the entire dependency tree into the MIT core repository.

Upstream revision and license/submodule inventory are in `UPSTREAM.json`. Run `scripts/checkout.sh` to create the isolated source checkout. Telegram sources, assets and derived client changes keep GPL terms and upstream notices. The D-MASH Node and credential/Account processes remain separate and communicate through the existing local framed API. No Telegram network account, SMS login or MTProto fallback is part of D-MASH.

The integration keeps the real Telegram navigation, dialogs, history renderer, composer, controls and assets. Root/Account authentication replaces Telegram authentication. Native encrypted Account storage is authoritative; Telegram presentation models are populated in memory only while logged in and cleared on logout/Root lock. Numeric peer/message IDs are local presentation identifiers with collision checks; Account public keys, operation IDs, network routes and cryptography stay unchanged. The client uses a D-MASH app-data namespace and must never open an installed Telegram `tdata` directory.

Current source checkpoint includes the original Intro Step with original Telegram
input widgets/styles for native unlock/login; Main::Account session projection;
original Data::Session contacts and History messages; and the original primary
composer calling account.sendText with a stable operation ID. The composer clears
only after accepted:true, and pending operation/sequence-zero rows use local
negative message IDs. Account logout/Root lock clears RAM presentation while Node
lifetime stays owned by the resident native host. This wiring is a draft and has
NOT passed full application compilation or real UI acceptance. Fresh setup,
imports, paging, all alternate send paths, media/calls, full persistence fencing
and process/network acceptance still require implementation and tests. Do not run
this draft against personal Telegram or D-MASH data.

The standalone Qt6.12 IPC/SessionAdapter library compiled. Full original app
configuration passes Qt (including matching Svg), Ada3.2.4 and Boost1.83, and now
stops at missing FFmpeg development libraries (protobuf3.21.12 now resolves).
tde2e/tg_owt/media dependencies remain to be built and audited. A separate optional
upstream widget bootstrap target is only a diagnostic build, never the selected
messenger application. No full fork binary or rendered fork UI is claimed.

`scripts/checkout.sh` reads the pinned revision, license, recursive gitlink map,
patch digests and final patched-file hashes from UPSTREAM.json. It refuses
unexpected existing changes before submodule mutation and never resets or cleans
a checkout. Upstream automatic updates and crash reporting are disabled explicitly
in the actual app configure script. License classification is in LICENSES.md.

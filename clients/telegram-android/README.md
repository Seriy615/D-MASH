# Actual Telegram Android fork

This client uses the pinned **DrKLO/Telegram 13.0.3** source, not a separate
recreation of its views. Original `LaunchActivity`, `DialogsActivity`,
`ChatActivity`, Cells, assets and ActionBar remain in that GPL client. The
independent D-MASH core retains its own MIT declaration; this does not relicense
Telegram or its dependencies. The upstream GPL text is included, and the pinned
checkout retains original notices and third-party licenses.

**Checkpoint status: complete Telegram Java module compilation passed at fork
`c6dfe2f` (137 Gradle tasks, 8m14s). No APK, Android service startup, Account/chat
or UI acceptance is claimed.**

`UPSTREAM.json` pins source, submodules, toolchain, license digest and the exact
patch series. `prepare.py NEW_CHECKOUT` clones and applies it without resetting
an existing checkout. `build.sh` builds a single arm64-v8a or x86_64 debug variant
with a supplied coherent D-MASH native Android deployment directory. It requires
SDK36, build-tools36, NDK27.2.12479018 and JDK21; upstream uses Gradle8.13 and
AGP8.13.2. MTProto initialization, request dispatch and native sockets are blocked. The focused third patch explicitly blocks fallback DNS, proxy probes and the upstream
update entrypoint. Patch four additionally blocks direct proxy setup, removes the library
Google-services plugin and Firebase initializer/push components, and gives the separately
namespaced app the D-MASH label. Patch four is awaiting the actual APK build; no network
acceptance is claimed. Initial authentication uses Root/Account rather than phone/SMS.

The actual UI reads Account contacts/history over the credential IPC and maps
public IDs to local numeric projection IDs with collision checks. Account
operation IDs remain in message projection metadata; sequence-zero pending rows
use negative local IDs. Outgoing rows do not fabricate recipient read receipts.
The existing foreground credential and Node services remain separate processes.
Root/Account auth replaces the initial Telegram SMS screen. Telegram SQLite
caches are memory-only and UserConfig saving is disabled; encrypted D-MASH
storage remains authoritative. Account logout and Root-lock status clear the UI
projection. Ordinary UI polling calls Account sync and refreshes actual history.

Initial source inspection found no tracked upstream AGENTS.md. A previous
standalone Qt-service APK had an unresolved failure before native ENTRY; copying
its Qt deployment files is not proof that the fork's services work. Final builds
must use the coherent core containing pairing_host.js and pending_sends.js, and
must pass actual service/UI tests on an owned profile. The initial Java compile
uses the old v6 Qt jars solely for compiler dependencies, with no runtime claim.

The focused third patch retains in-memory pending/error rows and the original operation/text
after an unknown IPC reply. The original composer clears only after durable acceptance.
A same-Account reconnect reconciles by operation ID; positive sequence alone does not mark
a message sent. Account fences clear plaintext projections and memory-only drafts.
`tests/test_pending_send.py CHECKOUT` exercises the actual projection source using deterministic
IPC/Android doubles; it is a unit gate, not service/UI acceptance. The full compile of this
patch passed the full Java compilation (137 tasks, 8m14s).

The matching D-MASH native credential and Node services compiled successfully for x86_64
from core source `139795f`, including pairing and durable first-send modules. No APK or
service startup result is implied by compiling those libraries.

Known unfinished areas include complete APK/native build verification, complete core deployment,
contact pairing controls, independent Node controls in the actual menu, full
error/cancel/reopen flows, and actual UI verification of the composer reconciliation.

Local builds may set `DMASH_TELEGRAM_CMAKE_DIR` to an exact CMake 3.22.1 installation.
The build recipe uses one shared Ninja job pool for compile/link tasks as well as one
Gradle worker. Initialized source is never reset to repair a failed build.

The first APK configuration attempts exposed a missing Ninja PATH entry and the
nonportable AndroidNdkModules CMake import. Patch six compiles the unchanged
pinned NDK CPU-features files directly. These are build findings, not service/UI
results. Ninja and NASM must be available on PATH.

## Actual fork KVM CI

`.github/workflows/telegram-android.yml` builds this pinned original fork and the
matching independent core from the same checkout, for x86_64 only. It reuses the
Qt/SDK bootstrap but never builds/runs the former standalone app UI or its
MainActivity/NodeDiagnostics harness. The real launcher is original
`org.telegram.ui.LaunchActivity`; package namespace is `org.dmash.telegram.beta`.

The default `loader` gate captures that actual window and requires the separate
credential service to reach the fresh Root-auth UI. `fresh-account` additionally
uses normal PIN confirmation, Account creation/login, original Saved Messages
ChatActivity/composer, and Activity background/reopen. Generated credentials are
never uploaded; password fields are redacted in XML, and only bounded native/Qt
loader diagnostics are retained. Build-only success and these scoped UI gates
never imply complete product acceptance. `full` intentionally fails after those
steps until the actual Node-control and ordinary remote-chat UI gates are wired.
Node/remote/Doze/reboot/multi-client UI remain explicitly NOT_RUN in that draft.

Evidence includes the exact source/dependency hashes, signature, APK/native ELF
hashes and actual screenshots. Package verification still fails on signature,
namespace, missing original classes/notices, unexpected ABI, mismatching bundled
core or 16-KiB alignment; available UI capture can run after that failure so its
separate observation is not lost. No existing app/profile is uninstalled/reset.
Final Account/UI acceptance requires the shared worker session binding and its
explicit attach adapter, not the older core139 compile checkpoint.

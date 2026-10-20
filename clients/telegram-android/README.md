# Actual Telegram Android fork

This client uses the pinned **DrKLO/Telegram 13.0.3** source, not a separate
recreation of its views. Original `LaunchActivity`, `DialogsActivity`,
`ChatActivity`, Cells, assets and ActionBar remain in that GPL client. The
independent D-MASH core retains its own MIT declaration; this does not relicense
Telegram or its dependencies. The upstream GPL text is included, and the pinned
checkout retains original notices and third-party licenses.

**Checkpoint status: complete Telegram Java module compilation passed at fork
`16b2cbf` (137 Gradle tasks, 8m42s). No APK, Android service startup, Account/chat
or UI acceptance is claimed.**

`UPSTREAM.json` pins source, submodules, toolchain, license digest and the exact
patch series. `prepare.py NEW_CHECKOUT` clones and applies it without resetting
an existing checkout. `build.sh` builds a single arm64-v8a or x86_64 debug variant
with a supplied coherent D-MASH native Android deployment directory. It requires
SDK36, build-tools36, NDK27.2.12479018 and JDK21; upstream uses Gradle8.13 and
AGP8.13.2. MTProto initialization, request dispatch and native sockets are blocked. Explicit
legacy DNS/proxy/update entrypoint guards are a follow-up; no network acceptance
is claimed. Initial authentication uses Root/Account rather than phone/SMS.

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

Known unfinished areas include complete APK/native build verification, complete core deployment,
contact pairing controls, independent Node controls in the actual menu, full
error/cancel/reopen flows, and original message-composer state reconciliation.

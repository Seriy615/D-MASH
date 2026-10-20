# D-MASH desktop client

Actual Qt Widgets executable for Linux/Windows source sharing. The executable links Qt Widgets/Network only; no mesh actor, Root/PIN or Account keys enter the Node daemon through this client. A separate credential owner supplies a one-shot inherited same-UID socket (`--session-fd N`) carrying a bounded owner-only handoff:

```
{v:1, endpoint, generation, role:"owner", capability, expiresAt}
```

The handoff socket is separate from the credential owner's daemon bootstrap lifetime lease. Closing/detaching the UI closes only its local client context. The client authenticates the daemon's existing `dmash-local-v1` owner scope and requests `node.status`. Capabilities are absent from arguments, logs and persistent UI settings. A stale handoff fails visibly; capability renewal comes from the credential owner, not a guessed daemon context. Same-user process compromise is outside this boundary.

Build with `native/platforms/scripts/build-desktop.sh` using the permanent owned Qt toolchain. On a development-header-free Linux host, download/extract `libgl-dev libglx-dev libopengl-dev libopengl0 libglvnd-dev` into `CACHE/platform-sysroot` without installing system packages. Build needs Qt6.12 Core/Network/Widgets/Test; offscreen tests do not require XCB. Windows uses `../windows/build.ps1`; Windows IPC attach is deliberately unavailable until the daemon's user-token/ACL seam exists, so Windows runtime is not claimed.

The client shows an honest locked/unintegrated Account state. Conversation/message controls remain disabled pending the existing Account facade, encrypted history import, contact binding and E2EE/receipt integration. This is the first service/status UI milestone, not an ordinary messenger or complete app. See `QA.md` for actual click coverage and limits. All source here is original D-MASH client code; no Telegram code, brand resources or GPL-derived widgets have been copied.

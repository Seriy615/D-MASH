# Integrated media and deletion UI release gate (source only)

All actions used synthetic Accounts/profiles and real EMS. User CDP9449 untouched. Page release `.29`, SW BLOCKED; final controller is null on both pages. No deployed-PWA/real-SW acceptance is claimed here.

## Integrated media source 6e9e867

Exact `6e9e867addc5fe9d95dfb581b2ffbf3d1540cf1b`. [Initial evidence](qa-media-integrated6e9.json):205 loaded responses all exact-match, no page errors; PUBLIC pair, key exchange/text both ways, three voice captures, durable saves, visible final delivery, hashes, relay/relay, no autoplay, offline persistence/reload/cancel/retry PASS. Stop-to-durable141/241/302ms; all three clips2.301s.

The initial run records26 PASS and one **TEST harness race**: immediately after logout, the helper checked for `+ НОВЫЙ ВХОД` before asynchronous registry rendering, skipped the actual click and waited for nonexistent #p1. The failure screenshot/text shows the healthy registry and new-login button. This outcome is preserved. The helper now waits for the gate before choosing a branch.

[Same-profile continuation](qa-media-integrated6e9-resumed.json) performed actual saved Account login, Account switch isolation, recipient ON→delivery, circle cancel/SEND/decode/no-autoplay (six PASS including restoration). Actual circle playback was additionally clicked and verified before changing source in the deletion run below. No profile reset, restart or extended timeout replaced the original failure.

## Actual deletion UI red3e → green668

[Full evidence](qa-delete-owner-ui.json), immutable snapshots:

- RED `3e70587cc9aad76ba3549650506914f4a5e500ea`:128 loaded responses exact. Storage preflight preserves peer/history8/known corrupt row/unknown opaque row, but actual Delete→ДА has no visible refusal, throws pageerror, revokes the peer epoch and removes its route. This confirms the ordering/UI bug, not a failure of the narrow Storage guard.
- GREEN `668be72ff419fb122fe00171b8a6f2f32c33fffb`:129 loaded responses exact, no page errors. Both Account identities survive source reloads. Delete→НЕТ leaves the state unchanged. Delete→ДА on the same corrupt test owner visibly shows `УДАЛЕНИЕ НЕ ВЫПОЛНЕНО`; peer/history8/known/unknown/notes6/peer epoch/route all remain identical. After removing **only the injected corrupt fixture**, ordinary Delete→ДА removes peer, eight history rows, media intents and route, while the unknown opaque row remains. UI success is visible.

The corrupt-owner fixture was inserted only if its synthetic target alias was absent; no existing owner record was overwritten. The retained unknown fixture is opaque; authenticated versioned journal preservation is covered by the separate N4 IDB mechanism test, not asserted from this UI fixture alone. Core ordering fix efb1b0d, integrated into668, is accepted by actual controls. A quick real voice send on3e and actual circle playback on6e also passed.

This is **N4 safety-only acceptance**: mixed-row preflight/atomic local deletion and UI ordering. It is not full N4 authenticated migration/recovery, full N0–N8 or an exhaustive UI DONE claim. Legacy pending media migration remains NOT RUN because old synthetic CDP9452 is unavailable. Final source668 requires publication verification/actual SW checks by the integrator. Media wire/runtime outside the deletion path was exercised on6e; the exact668 delta gate covers fresh source load and deletion UI.

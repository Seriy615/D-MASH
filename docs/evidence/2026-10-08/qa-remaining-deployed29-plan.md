# Remaining browser acceptance plan after deployed `.29`

Target source: `5a2439834a2fc22db8f6ecd0b9674d533397ea8a` on
`https://messenger.d-mash.ru/not_messenger/`. A separate exact-source report
exists for the deployed two-profile PUBLIC/media/delete gate. This plan does
not promote that narrow gate to N0–N8 completion. Use fresh synthetic browser
profiles for every destructive flow; never clear a real profile or reuse
CDP9449. Capture page build and active controlling SW build, loaded response
hashes against the target commit, visible controls and their disabled state,
action timestamps, page errors, and transport observations. Keep credentials,
Account IDs, keys, payloads and raw browser storage out of publishable evidence.
An interrupted locator remains a harness interruption until the same profile
is inspected; do not reset it to manufacture a PASS.

| Priority | UI rows / exact action sequence | Required visible and independent assertions |
| --- | --- | --- |
| P0 | UI02 Account deletion: create two synthetic Accounts with separate Saved Messages; global Account manager → delete B → cancel; repeat → type `УДАЛИТЬ` → confirm → recreate B with the same credentials | Cancel preserves registry/history; confirm follows its explicit erase warning, removes only B's owned data and never A; verify after reload/relogin, including encrypted stores and orphaned rows. Current `.29` visible-history assertion FAIL; implementation owner to be assigned. |
| P0 | UI07/UI08/N3/N4 on the ordinary Node host candidate: PUBLIC and PRIVATE contacts, Request/Accept/Confirm, key exchange, text both ways, peer offline/reconnect, Account switch/logout/lock, stale peer recovery | Actual buttons and visible status after each action; separate proof that packets use `NodeRuntimeHostV4` with one NODE wire role, authenticated state/mailbox migration and retained pre-upgrade identity/history. `.29` v3 path does not satisfy this. |
| P1 | UI04/N6 controlled private Node: import signed Node descriptor, connect with missing/wrong/correct password, replay proof, disconnect/reconnect, delete cancel/confirm, resource operations before/after auth | Wrong/missing/replayed proof cannot access peer/store/route resources; correct proof grants only scoped operations; visible error/retry and no raw password in URL query/localStorage/log. Use controlled test Node; no production credential rotation. |
| P1 | UI05/UI06/UI07: QR show/copy/scan with denied/running/delayed camera; malformed/old/missing-contribution import; public/private create/advertise/disable/delete/re-add; pending decline/cancel/restart | Each button and modal Back/Close/Cancel; copy contents decoded and verified without publishing them; route ready timeline and failure shown honestly. Reproduce `ROUTE-READY-01` with timestamped REGISTER/Probe/status evidence rather than longer timeout. |
| P1 | UI11/UI12/N7 paired Accounts: call start → incoming accept/decline → mute/video/audio/speaker/screen switch → hangup; forced TURN and direct ICE separately; file request → consent/reject → progress/cancel/complete/download/hash/expiry | Actual UI clicks plus RTC selected candidate pair/relay counters and integrity; denied media permissions, expired ticket, locked Account, large-file bound and ringtone/caller display. Existing voice/circle relay gate is narrower. |
| P1 | N2/N8 real transport: Python N1 → browser B → Python N2 with B logged out of Account, then B sleep/close and alternate path | Capture source/destination Node role, label replacement, B receive/forward, no bypass and opaque Account payload. Observe honest unavailable or alternate delivery after B goes away. Repeat on exact candidate SHA, not historical fixture only. |
| P2 | UI01/UI03/UI09/UI10: calculator/master/wipe and rewrap retained Account; Saved Messages password set/wrong/correct/remove; chat rename/delete/read; voice/circle permission, capture cancel/send/play/pause/retry/download/Account switch | Reuse actual UI controls on current SHA; preserve historical errors. Physical orientation, real camera and WebAuthn need suitable devices and remain NOT RUN in headless Chromium. |
| P2 | UI13/UI14/E6: notification consent/click/locked neutral display/wake/reconnect; enumerate every dynamic modal/menu control from runtime DOM at each state | Confirm no Account semantics leak to Origin/signaling; verify local history protection remains distinct from transport; log each discovered control PASS/FAIL/NOT RUN. |

For each browser case, record `precondition → locator/action → expected → actual →
PASS/FAIL/NOT RUN → bug owner/fix SHA/retest`. A unit or console call can support
the result but cannot replace the visible UI action. Backend security, migration,
installer and cryptographic checks in N5/N6/N8 require separate fixtures and
review; a browser click alone cannot prove them.

# DEPLOYED 5a24398 independent UI acceptance

Target `5a2439834a2fc22db8f6ecd0b9674d533397ea8a`, actual HTTPS EMS PWA, no overlay, service worker enabled. Both final pages and active controlling SW report `transport-v3-node-preparation-20261008.29`. Fresh synthetic PUBLIC Accounts only; user CDP9449 untouched. Identities/profiles retained on CDP9490; no storage reset.

[Original run](qa-deployed5a-media-delete.json) preserves six successful setup/request checks and the original `public-accept-account` locator failure: an actual incoming-contact notification replaced Settings and detached its control. [Same-profile continuation](qa-deployed5a-resumed.json) acknowledges that notification with the UI, then completes 27/27 checks. This is not an uninterrupted 33-check run. No transport failure is inferred from the first locator interruption.

Continuation loaded 206 response bodies, all matching exact target bytes; 122 were served through the SW. Both final page/SW versions match; page errors empty. Connected Node STATUS reports both `can_s_turn` and `can_relay_blob` true.

| Actual controls / visible or durable assertion | Result |
| --- | --- |
| PUBLIC Request → notification OK → Settings/Pending Accept → Confirm; key exchange; text both directions | PASS |
| Voice capture Cancel; three short record/SEND; three durable notes; visible delivered status without reopening | PASS |
| Receiver decrypt, equal content hashes, readyState4, no autoplay; native play/pause | PASS |
| RTC selected relay/relay, relay-only policy; observed Account boundary carries metadata rather than legacy media body | PASS |
| Peer OFF, pending note persisted, reload and saved-Account login | PASS |
| Visible Cancel retains local payload; visible Retry; Account switch isolation; peer ON and bounded recovery | PASS |
| Circle capture Cancel, record/SEND, decrypt, no autoplay, actual playback | PASS |
| Contact deletion Cancel; corrupt-owner visible refusal without side effects; valid deletion preserves unknown row | PASS |
| Legacy pending-fragment upgrade from .26 | NOT RUN: retained CDP9452 unavailable; not recreated or reset |
| Physical devices, large-note consent, complete calls/files/recovery inventory and full N4 migration | NOT RUN in this slice |

Voice SEND→durable times: 203/251/263 ms; clips each 2.301 s, payloads each 30,532 bytes. All three delivered 45.641 s after first durable save. Fast local save does not establish uniformly fast final delivery. Each observed application metadata invitation was 777 bytes before encryption/wire overhead. RTC counters are per-session observations, not proof of total server traffic or twofold bandwidth savings. Circle duration 2.3499 s; readyState4, paused/autoplay false before actual playback.

Delete fixture is synthetic. Refusal preserves peer, seven history rows, known/unknown owner rows, five note records, route and unrevoked peer epoch. After removal of only the injected corrupt row, actual valid deletion removes the target/history/known owner/notes/route and revokes its epoch; unknown opaque row and Account identity remain. This is N4 safety-only. Authenticated versioned-row preservation is a separate mechanism gate, not established by an opaque fixture alone.

Earlier a524 reload-control and responsiveness failures, and red3e deletion ordering failure remain historical evidence. Deployed retest closes the exercised reload-control and delete-ordering UI gates. Delivery latency variability remains measurable; no universal latency claim. Full N0–N8/A–M/E6 completion is not asserted.

Lead deployment provenance (not independently re-read backup contents): exact verifier255/255; identities SHA preserved; three DB quick_check; real UDP/TCP/WSS PASS. Rollback references: PWA `/srv/messenger.d-mash.ru/backups/manual-rollback-20261008T034827Z`; backend `/root/dmash-runtime-backups/sturn-gateway-gate-20261008T034751Z` and `/root/dmash-runtime-backups/backend-exact-20261008T035123Z`. No backup contents or user secrets are included.

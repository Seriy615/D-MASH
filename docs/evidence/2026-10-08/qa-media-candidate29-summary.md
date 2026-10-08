# Independent recorded-note UI acceptance — candidate a524bc0

Exact PWA source `a524bc0520013e6311158faac980774c5dc86efb`, immutable same-origin overlay; both pages `transport-v3-node-preparation-20261008.29`, service workers BLOCKED. This is BROWSER acceptance with real EMS transport, not DEPLOYED PWA acceptance. Fresh synthetic PUBLIC pair only; user CDP9449 and earlier baseline CDP9452 untouched. Retained browser CDP9460, primary handle82969. Both connected Node STATUS responses explicitly reported can_s_turn=true and can_relay_blob=true. 138 initial loaded response bodies match the candidate; after reload, independent CDP loaded-script source verification matches all100 captured scripts.

| Scenario | Result | Evidence / limits |
|---|---|---|
| Fresh PUBLIC Request/Accept/Confirm, key exchange, text both directions | PASS | `qa-media-candidate29.json`; original180s handshake deadline retained |
| Voice capture cancel | PASS | Actual X; no durable note added |
| First voice save/decrypt/playback | PASS | First stop-to-durable239ms; sender visibly delivered, receiver actual native playback |
| Three consecutive voice saves | PASS | Same profiles; no queue-full rejection; each intent retained before transport |
| Visible final delivery without reopening | PASS | Three notes all show delivered |
| Voice content integrity / receiver readiness | PASS | Three blob SHA-256 values compared to sender intents; only equality exported; readyState4, paused, autoplayfalse |
| S-TURN route and no legacy fragment path | PASS in observed scope | Both peers selected relay/relay with relay-only policy; observed Account send boundary contains three777–778B metadata invitations, no media/legacy fragment frames. CDP observational logpoints may affect timing; this is not plaintext inspection of encrypted network packets |
| Voice responsiveness | OPEN / FAIL fast-send expectation | Stop-to-durable438ms,6764ms,548ms. Actual durations2.361s,7.591s,2.481s despite intended2.3s captures. All three delivered by29.1s after first durable note. UI scheduling/admission contention suspected, not causally proven |
| Peer Node OFF → durable waiting | PASS | Actual Node OFF, retained local payload |
| Reload → saved Account → original chat | PASS persistence | Same profile, pending intent retained |
| Cancel/retry after reload | PRODUCT FAIL | Chat has generic ОЖИДАЕТ but no `.note-transfer-state` or Отменить отправку for30s. Owner qa_account_media; hydration fix requires new candidate retest |
| Account switch isolation | PASS | New synthetic Account has only Saved Messages and no note intents; returning original restores five intents including pending payload |
| Reconnect delivery within90s | FAIL bounded observation; eventual delivery confirmed | Actual recipient ON; original90s deadline expired. Later metadata shows pending note delivered on attempt4. Backoff can exceed90s; do not infer absent wakeup from deadline alone |
| Circle cancel / SEND / delivery | PASS | Actual capture X, then2.3s capture/SEND;148004B delivered |
| Circle decode / no autoplay / playback | PASS | Distinct РАСШИФРОВАТЬ КРУЖОК clicked; readyState4, duration2.3489s, paused/autoplayfalse, actual playback click |
| Durable cancel/retry, legacy media_outbound migration, peer deletion, large-note consent | NOT RUN / blocked | Cancel/retry blocked by original hydration defect; others require separate fixtures/actions |

Preserved harness/control failures, not hidden: initial second SEND role lookup timed out while recording (cause unresolved; later stable `.send-btn` clicks worked); first reload helper incorrectly waited for hidden #p1 instead of the saved Account button; a continuation tried reading absent receiver #p1; first circle helper clicked the preceding voice's generic decrypt rather than the distinct circle control. These original files remain unchanged in outcome. Corrected actions used the same profiles, without data reset or timeout inflation.

Evidence: `qa-media-candidate29-resumed.json` contains10 successful online checks; `qa-media-candidate29-lifecycle*.json` preserve reload/control findings; `qa-media-candidate29-switch-circle.json` preserves bounded reconnect timeout; `qa-media-candidate29-circle*.json` separate the selector assumption from final correct decode/playback. `qa-media-candidate29-retry-state.json` records03:11:43 all six notes delivered, both Nodes ready, no pending protocol requests or note tasks. Miner handed back then; browser retained without new network tests. No full N0–N8, complete UI inventory, physical audio/video quality or final deployed acceptance is claimed.

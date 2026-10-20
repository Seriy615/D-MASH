# Native Widgets UI checkpoint

This is Linux native Qt Widgets acceptance using QtTest mouse events with the offscreen Qt platform plugin. It is not BROWSER or DEPLOYED acceptance. Qt 6.12.0, GCC13.3, source and binary hashes are in `evidence/checkpoint.json`. No service worker is involved.

| Control/flow | Result | Evidence/limit |
|---|---|---|
| Detached startup | PASS | Visible status, disabled refresh/detach/compose/send; read-only history |
| Application details → Close | PASS | Real button click opens modal; Close click dismisses it |
| Invalid broker descriptor | PASS | Visible failure; controls stay disabled |
| Attach separate actual Node host | PASS | One-shot same-UID owner capability handoff; visible live node.status |
| Refresh Node status | PASS | Actual button click, real local IPC response |
| Detach UI | PASS | Actual button click; service process remains alive |
| Close UI | PASS | Daemon remains alive until broker lifetime lease closes |
| Conversations/compose/send | PASS (Saved only) | Actual encrypted Account storage.js Saved path; ascending native bubbles, send, sign out/reopen retained |
| Full profile file chooser / Cancel / Device PIN | PASS | Complete secure registry imported through broker; no new identity fallback |
| Account chooser / Cancel / wrong password / busy Cancel / login | PASS | Actual modal mouse/key actions and visible disabled/error states |
| Account original Saved history / logout / restart | PASS | Original history retained, native write retained after Root unlock and Account re-login |
| Remote contacts / pairing / chat / media policy | NOT RUN | Requires resident credential host + authenticated route and ordinary contact flows |
| Windows executable/package/runtime | NOT RUN | Portable source + owned build script only |
| Android Activity/service/device | NOT RUN | Separate implementation/build acceptance, no equivalence with Linux |

`tests/ui_test.cpp` inventories visible controls and clicks the modal close path. `tests/live_ui.py` starts a separate real actor with synthetic scoped materials and performs the attach/refresh/detach path. Its Node has no mesh endpoints; prior transport acceptance elsewhere does not turn this into a chat or transit gate. Default tests use a complete synthetic secure profile; parent may provide a private retained-profile wrapper through test-only DMASH_ACCOUNT_UI_FIXTURE. Tests never reset a source profile or log tokens/passwords. Imported app-local key is a private development file, not a hardware vault; preserve the whole native profile including app-local.key for backup. Bug owner: native_platforms_sol. The current resident checkpoint owns Root, Account and Node bootstrap lifetime in a separate credential process. The UI uses framed private local IPC and does not link Account/broker libraries. Full CTest control gate PASS4.75s; real UI Account actions followed by SIGKILL of the UI process leave the credential host and actual Node running. Explicit Root lock confirms the owned Node stopped. Node enable in that lifetime gate used harness IPC, not a visible UI button; no mesh endpoints were configured. Source/binary/runtime hashes are in evidence/resident-checkpoint.json. The former direct-worker Account checkpoint remains historical evidence only. Fresh setup, remote contact/chat, visible Node controls, Android Account UI and Windows runtime remain open.

Visible Node controls now have a separate exact frozen Linux acceptance in `evidence/node-controls-checkpoint.json` and `evidence/node-controls.json`: actual Connections Add/invalid Start/error/Remove/direct toggle/Cancel; Start Node launches the real native child; sign out and Refresh retain it; Stop Node & lock confirms exit; PIN/relogin retains Saved. PASS27.696s, basic CTest PASS4.69s. No mesh endpoints were configured. `tests/node_controls.py` uses only a fresh synthetic Node fixture before import; a caller-supplied profile is unchanged. The resident capability lifetime is still bounded while corrected lease extension is pending. Android and Windows execution remain separate gates.

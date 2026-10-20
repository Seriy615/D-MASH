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

`tests/ui_test.cpp` inventories visible controls and clicks the modal close path. `tests/live_ui.py` starts a separate real actor with synthetic scoped materials and performs the attach/refresh/detach path. Its Node has no mesh endpoints; prior transport acceptance elsewhere does not turn this into a chat or transit gate. Default tests use a complete synthetic secure profile; parent may provide a private retained-profile wrapper through test-only DMASH_ACCOUNT_UI_FIXTURE. Tests never reset a source profile or log tokens/passwords. Imported app-local key is a private development file, not a hardware vault; preserve the whole native profile including app-local.key for backup. Bug owner: native_platforms_sol. The Account checkpoint currently owns broker/Account workers inside the UI process and does not spawn a Node supervisor. Closing this Account UI terminates its credential worker; the separate old live-service fixture only proves an externally owned daemon lifetime. Resident credential host, fresh setup/create Account, remote contact/chat, Android Account UI and Windows runtime remain open. Final Account source/binary mapping is in evidence/account-checkpoint.json. QtTest uses real QWidget events with offscreen rendering; this is not an Android or Windows runtime result.

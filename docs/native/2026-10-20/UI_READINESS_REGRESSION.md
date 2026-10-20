# UI-BOOT-CONVERGENCE-01 — scoped baseline repair

The original release installed repair wrappers with 30–120 second timer deadlines. Core, DeviceRoot and Storage load only after calculator unlock. A delayed unlock therefore loaded Core after most installers had stopped: stock Account settings remained visible and `Core.beginKeyExchange` was missing. The historical early/late browser observations are preserved separately in [Browser QA](BROWSER_QA.md); a host reboot destroyed those original profiles and raw logs.

The candidate adds a small synchronous readiness registry in `release.js`. Support modules register idempotent stages with explicit dependencies. Shell/UI stages run before unlock; the actual lazy foundation loader awaits ordered composition before reporting readiness. Existing wrapper bodies, crypto/KDF, payloads, wipe implementation and transport protocols are unchanged. The biometric cold-start warmup remains after the loader is available. The existing bounded fallback installers remain for standalone/raw-module consumers without the release registry.

Dependencies are evaluated inside error handling; pending stages fail foundation readiness rather than silently accepting a partial UI. Foundation's existing failed-task clearing permits retry. `supportLoaded` clears an earlier support error. Current installers are synchronous; returning a Promise is an installation error. Original asynchronous work started inside wrappers (metrics/background assets) retains its original lifecycle. This change does not assert those operations have completed when wrapper composition completes.

The actual-source unit regression loads the release and real installer modules in a VM with a deterministic clock and minimal collaborator fixtures. Both 1-second and 180-second deferred Core loads must produce the same required markers and real key-exchange handler. Five recompositions retain function references and create no registry polling timers. An actual v50 `.bind` failure must reject foundation readiness; restoring the dependency must permit retry. Additional cases cover throwing readiness predicates and support failure/recovery. This is a lifecycle unit test, not cryptographic or real Node acceptance.

Run with Node 24.19.0:

```sh
node 'D-MASH PWA/not_messenger/tests/ui_runtime_readiness.test.js'
DMASH_UI_READINESS_SOURCE_REF=9446c22f27309131456942870971d477f6f2358f node 'D-MASH PWA/not_messenger/tests/ui_runtime_readiness.test.js'
```

The baseline command is expected to fail: `__dmashFunctionalRepairV2 after 180000ms` is undefined. The candidate command passes. Seven adjacent focused tests also passed: `ui_global_bridge_source`, `public_request_preparation`, `password_prompt_worker_regression`, `pending_contact_ui`, `account_login_identity`, `node_account_panel_status_v4`, `node_runtime_host_v4`. No full-suite result is claimed here.

The independent browser harness uses Playwright's library, two fresh synthetic contexts, actual UI clicks and the real bundled crypto/WASM. It accelerates all elapsed timers with `clock.runFor`; it does not wait 180 wall seconds or mock crypto. Loopback HTTP is allowed; external HTTP, WebSockets and ServiceWorkers are blocked. The harness serves actual candidate files and records hashes of the served bytes. Reproduce with an installed Playwright package and Chromium:

```sh
DMASH_PLAYWRIGHT_MODULE=/absolute/path/to/playwright \
DMASH_CHROMIUM=/absolute/path/to/chrome \
node tools/test_ui_runtime_readiness_browser.cjs
```

[Browser result](ui-readiness-browser.json) records each completed visible step, required markers, effective handler hashes, public identity hashes and served source hashes. It exercises calculator setup/unlock, Account login, Account settings, PRIVATE QR/PUBLIC empty state, Saved Messages send and same-context reload/history retention, and the raw offline contact's explicit pairing-required key-exchange error with an enabled retry action. No console invocation substitutes for these actions; read-only state inspection checks identity/markers.

During harness development, incorrect selectors caused failed runs: nonexistent submit handler; ambiguous ID/network card selector; first QR canvas hidden by the QR library; exact message text including its delete control; Saved back button lacking the generic `back-btn` ID; and counting history before async rendering. These failures were preserved in the durable tool cache and corrected against actual source. They are harness failures, not product PASS or hidden product retries.

This is a focused baseline bugfix. It does not close the all-controls gate, authenticate an offline raw contact, establish positive peer/network/file/call behavior, implement native clients, or retest the lost historical profiles. [Control inventory](UI_CONTROL_INVENTORY.md) and Browser QA retain outstanding cases. Parent integration/retest is separate.

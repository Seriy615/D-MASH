# BIO-ENROLL-CANCEL-01 — trigger setup can exit safely

The original `ui_logic.handleBiometricHold` caught a failed enrollment by clearing display text while leaving calculator mode 6 active. The selection screen had no Cancel. The new focused regression reproduced this as `6 !== 0` before the fix.

The candidate changes only `ui_logic.js` production behavior. Mode 6 shows an explicit **ОТМЕНА ПРИВЯЗКИ КНОПКИ** button. Cancel clears an unfinished hold/qualification and returns to Global Settings while the same DeviceRoot remains unlocked; a locked/replaced root leaves the neutral calculator. A false/throwing enrollment exits mode 6 as well. Existing successful setup still saves the selected public calculator trigger and returns to ordinary calculator mode.

Selection accepts the same tokens as configured-trigger lookup. Holding AC, ± or = cannot create an unusable trigger. Instructions use the effective hold duration (v54 currently sets one second). Short taps remain ordinary input. Only one enrollment request may run at once; completion checks the setup instance and DeviceRoot session before changing the trigger. Cancel/reentry and root replacement invalidate an old completion. Immediate failure preserves suppression of the originating pointer-release click.

**Boundary:** Cancel stops trigger selection. `Core.setupDeviceBiometrics` and DeviceRoot/WebAuthn credential bodies are unchanged. Their API has no AbortSignal, so this UI change does not abort an open OS credential prompt, roll back an already completed credential operation, or claim cancellation of native platform enrollment. The browser/OS provides its own prompt cancellation. A late result cannot commit a trigger into a cancelled/new setup. Positive platform PRF enrollment remains NOT RUN in this headless browser pass.

Node 24.19.0 focused checks passed:

```sh
node 'D-MASH PWA/not_messenger/tests/biometric_setup_cancel.test.js'
node 'D-MASH PWA/not_messenger/tests/global_settings_ui.test.js'
node 'D-MASH PWA/not_messenger/tests/calculator_secret_gate.test.js'
node 'D-MASH PWA/not_messenger/tests/historical_webauthn_release.test.js'
node 'D-MASH PWA/not_messenger/tests/ui_runtime_readiness.test.js'
```

The actual-source unit covers failure, explicit cancellation, valid/invalid tokens, instruction duration, duplicate requests, late completion after cancel/reentry, root replacement and clearing an unqualified hold. The existing Global Settings fixture now supplies real DOM creation/removal primitives and asserts the cancellation control lifecycle. No full-suite PASS is claimed: the earlier full runner remains recorded as FAIL, with its single historical WebAuthn harness incompatibility corrected separately in commit `44606714cb68608f37cda964035b4e65bba008b8`.

[Browser evidence](biometric-setup-browser.json) is a fresh real Chromium pass with six visible steps. It uses the immutable PWA tree from `44606714cb68608f37cda964035b4e65bba008b8`, overlaid only with candidate `ui_logic.js`, because another agent was developing DeviceRoot credential foundations concurrently. All served byte hashes are checked against that baseline plus overlay. The test performs actual calculator setup/unlock, intro Back, explicit Cancel, real pointer holds of invalid tokens, a valid short tap, a valid hold leading to actual headless WebAuthn refusal, and repeat setup/cancel. Device public identity and encrypted record hashes, trigger value, calculator state and absence of Account login are checked before/after. External HTTP, all WebSockets and ServiceWorkers are blocked; crypto/WASM are the real bundled baseline implementations.

The first browser attempt used the wrong expected settings title; its failed report was preserved in the durable tool cache. The harness was corrected to the actual repaired title, «ОБЩИЕ НАСТРОЙКИ». No product workaround was used.

Reproduce from an immutable fixture with the candidate overlay:

```sh
DMASH_PWA_ROOT='/absolute/fixture/PWA' \
DMASH_PLAYWRIGHT_MODULE=/absolute/path/to/playwright \
DMASH_CHROMIUM=/absolute/path/to/chrome \
node tools/test_biometric_setup_browser.cjs
```

This proof does not cover the concurrent credential migration implementation, physical biometric hardware, Account biometric login or all-controls/native acceptance. Parent integration testing remains required after the independently owned source changes are composed.

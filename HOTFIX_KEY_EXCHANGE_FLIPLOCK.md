# Key exchange feedback and Flip-Lock hotfix

Parent: `3c51360` (.26 production source). This patch contains no Node V4 cutover.

The initial chat renderer used an inline sendMessage handler; the repair layer
attached beginKeyExchange only during pagination. The initial button therefore
had no pending feedback. The repaired handler also referenced the browser's
native window.Storage constructor instead of the exported application storage.
The initial render now calls beginKeyExchange directly, which captures its peer
and Account/vault context, immediately disables the control and shows status,
refuses concurrent clicks, handles false/error results visibly, and does not
claim the channel is established merely because the request was submitted.
A cancelled send does not enqueue after its session guard becomes false.

Later settings renderers omitted Flip-Lock from both Global and Account Settings.
Both surfaces now expose the same device-wide preference. Global toggling returns
to Global Settings; Account toggling keeps the Account modal. Existing opt-in,
call, recording and suppression guards remain unchanged.

Validation:

- Deployed .26 baseline independently found both Flip-Lock controls absent.
  A real two-profile key exchange eventually completed without immediate feedback.
- `key_exchange_feedback.test.js`: pending feedback, duplicate click, native DOM
  Storage shadowing, false/error response, peer/session cancellation and no late
  queue; Global rerender and opt-in/call/recording/suppression guards PASS.
- Existing lifecycle and acceptance source tests PASS.
- Corrected Chromium 156.0.8078.4 actual UI run: 16/16 PASS, 138 ms feedback,
  initial DOM handler verified, real public Request/Accept/Confirm, key exchange,
  messages in both directions, Account and Global OFF→ON→OFF, and retained history
  after logout/login. 136 served-source observations matched the isolated files.
- First prototype failed on the exposed window.Storage bug and was corrected.
  Second run was interrupted by a legitimate incoming-contact popup; the harness
  now retries only that known popup through actual OK clicks, without force-click.
  Both failed reports are retained alongside the final PASS.

Evidence is local .26 source overlay with service workers BLOCKED, not deployed
or exact release/SW acceptance. Physical orientation is NOT RUN on desktop;
synthetic event guard tests do not replace a mobile sensor check. Independent
exact-source and deployed page/SW acceptance remains the integrator's gate.

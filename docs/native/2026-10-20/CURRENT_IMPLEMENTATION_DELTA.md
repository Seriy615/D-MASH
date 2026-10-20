# Current implementation delta — 20 October 2026

[CURRENT_HANDOFF.md](../../../CURRENT_HANDOFF.md) is the current acceptance
summary. This document describes the integrated native core through `3a72492`
and Android source-verification followup `0b804bf`. The
[9446c22 audit](../../audits/2026-10-20/CURRENT_IMPLEMENTATION.md) remains historical.
Android, Windows and Linux applications are unfinished. No deployment occurred.

The selected frontends are **actual forks of Telegram Desktop and Telegram
Android**, retaining their UI/components/assets/navigation. Independently drawn
Widgets/Views clients are stopped intermediate harnesses. Their screenshots and
bounded tests do not satisfy the user's exact-clone requirement. Fork recipes,
upstream pins, licenses and patches live in
[Desktop](../../../clients/telegram-desktop/README.md) and
[Android](../../../clients/telegram-android/README.md). GPL notices remain in
clients; this does not relicense upstream client code as MIT.

| Area | Implemented and independently checked | Remaining boundary |
| --- | --- | --- |
| Local credentials | Versioned Root wrapping, retained identity/history migration and worker cancellation. [Migration](root-s01-retained-migration.json), [cancel](root-s01-worker-cancel.json). Account's original Argon2d derivation remains compatible. | Full hardware/OS/crash matrix; existing identities must not change for a green test. |
| Node daemon | Separate Qt/QuickJS process; opaque encrypted queue/Inbox and actual foreign transit without Account login. [Actor](root-native-actor-interop.json), [fresh zero-Account transit](root-fresh-zero-account-transit.json). | Configured loopback peers do not establish NAT mobility, self-organization or all-platform service lifecycle. |
| Storage/ownership | Encrypted records in SQLite, CAS/quota/owner checks; retained Account identities and original Saved history; atomic initial import. [Inbox](root-native-inbox-verification.json), [Account](root-native-account-retained.json), [import recovery](root-account-import-recovery.json). | SQLite shape/size metadata remains visible. Initial import is not complete authenticated mailbox migration/N4. |
| Resident owner | Account logout/UI death preserve unlocked Node; Root lock stops it. Private lease extension preserves the same live authorization context. [Host](root-resident-credential-host.json), [recovery](root-resident-host-recovery.json), [lease](root-native-capability-lease.json). | Full OS restart/suspend and N4 fault matrix remain open. Original unexplained bootstrap/admission failures remain recorded in CURRENT_HANDOFF. |
| Transport pause | Pause retains pending opaque work, identities and history; resume needs no PIN. Root tested host crash/reopen while paused and delivery once after resume. [Proof](root-native-pause-process.json). | Actual fork settings/buttons need UI acceptance. Pause and full Root lock have different effects. |
| Private contacts | Fresh native Accounts pair through signed request/accept/confirm with real Kyber and Node forwarding, without injected contacts/routes; bilateral history survives relogin. [Proof](root-native-private-pairing.json). | UI QR/contact flows, public contact IPC and phone NAT remain open. Bundled Kyber compatibility is not a standardized ML-KEM/PQ claim. |
| First message | Account-owned encrypted pending queue accepts a send before E2EE readiness; ordinary sync delivers automatically after logout/host crash/reopen without caller resending. [Actual proof](root-native-first-send.json). Strict transient handoff followup preserves accepted pending state and rejects corruption/conflicts. [Retest](root-first-send-transient-retest.json). | UI clock/delivery states must follow actual receipts. Native queue acceptance is not remote DELIVERED or READ. |
| Remote replay/recovery | Actual recipient crash after durable history before consume, and recipient Node restart with lost accepted-job reply, preserve identities and one application row. [Remote](root-native-remote-account.json), [retry/restart](root-native-account-retry-node-restart.json). | Scoped Linux text fixtures, not complete ratchet/file/N4 recovery. |
| Actual Desktop fork | Pinned upstream and real LocalClient compile; root independently invokes real host through that adapter for Root/Account/Saved/logout/lock. [Proof](root-actual-fork-ipc.json). Main UI/session/composer integration is in progress. | Adapter probe is not the full Telegram application. Full Linux/Windows target build, render and UI/no-egress acceptance remain open. |
| Actual Android fork | Pinned upstream patch retains LaunchActivity/DialogsActivity/ChatActivity and connects Account projections to our service. Telegram network disabled in source; UI caches memory-only. Prepare script verifies upstream/license/submodules/patched file hashes; root's 8 synthetic provenance tests pass. | Actual fork Java compilation is in progress; no full fork APK/service/UI acceptance yet. Earlier intermediate service hit pre-ENTRY loader failure, whose exact runtime cause remains unresolved. |
| Earlier platform harnesses | Linux custom UI scoped flows and Android launcher KVM controls passed. Windows compiled 75 targets and later direct disconnected QtTest 3/0 passed; mandatory full CTest still failed. | These are intermediate/component evidence, not selected frontend or release acceptance. |

## Verification and remaining product work

The frozen `3a72492` reference runner completed with exit0: **303 backend tests,
22 Origin tests and 162 JavaScript suites**, Python3.12.3 and Node24.19.0.
[Source/log hashes and limits](root-reference-3a72492.json). This does not assert
an exact dirty-HEAD pass, browser UI pass or full native app build.

The browser inventory still has 178 control classes with scoped PASS/FAIL/NOT RUN
in [BROWSER_QA](../../../BROWSER_QA.md). Actual clicks, visible outcomes and a
separate real transport remain mandatory. API calls and component HTML cannot
replace normal user flows. Earlier source `.43` browser checks are historical;
source page/SW `.45` has not been deployed or fully accepted in a browser.

Remaining product work includes both actual fork integrations, packages and
ordinary Account/contact/chat/settings/file/media flows on all three platforms;
self-organizing peers, direct NAT connections and policy relay; public contacts;
full authenticated state/mailbox migration and N4; configurable encrypted file
providers and security policies. Existing files still have the original 64 MiB
limit, whole-file memory costs and non-resumable flow. New provider custody is not
implemented. DHT remains out of scope.

[THREAT_MODEL.md](THREAT_MODEL.md) describes the trust boundaries and residual
limits. Do not infer anonymity, PFS/PCS/PQ, network custody ACK, secure memory
erasure or complete application readiness from the component results above.

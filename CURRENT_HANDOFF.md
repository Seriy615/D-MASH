# D-MASH — текущий хендофф

**20 октября 2026 UTC. Цель ACTIVE. Android, Windows и Linux приложения НЕ ГОТОВЫ.**

Последнее явное уточнение: «Делай прям клон телеграмма… Не отдалённо похожее
а именно клон». **Использовать форки самих Telegram Desktop и Telegram Android**,
сохраняя их реальные UI/components/assets/navigation/behaviour; под ними наш
Account/core/Node daemon. Самостоятельная похожая QtWidgets/JavaViews перерисовка
ОСТАНОВЛЕНА. Ранние скриншоты и UI PASS — только промежуточная инфраструктура,
не приёмка требуемого клиента. GPL клиентов и их notices сохраняются, отдельное
MIT ядро остаётся независимым. Telegram backend/MTProto не является fallback;
D-MASH не требует Telegram SMS/login. Форки воспроизводятся pinned upstream +
открытыми patches/build scripts в clients/telegram-{desktop,android}.

Прежнее совместимое указание «аккуратно думай не сильно о кибербезе» сохраняется:
обычная переписка, автономная Node, простой UI и сохранность данных. Исправлять
подтверждённые ошибки без гипотетических церемоний. Этот файл — единственная
текущая сводка; docs/archive и Git history не задают текущие SHA/критерии DONE.

## 1. Цель, checkout и обязательные границы

- Checkout `/home/jcode/D-MASH`, branch `codex/native-clients-20261020`, host
  `forgeai.isgood.host`. `/home/jcode/D-MASH-Gamma` — прежний WIP, не менять.
- Полная цель: проверенные Android + Windows + Linux приложения, общий Node
  daemon, обычные Account/contacts/chat flows, самоорганизация без DHT,
  NAT/direct/policy relay, durable очереди/Inbox, временные encrypted file
  providers, гибкие политики, MIT ядро/GPL заимствования и полная документация.
- [План N0–N8/A–M/E6](D-MASH_Codex_Development_Plan.md) остаётся обязательным.
  Не подменять его зелёной v3 регрессией или отдельным component PASS.
- Единственная wire role NODE; устройство пересылает реальный чужой transit без
  Account login. Account владеет E2EE/контактами/plaintext/history; Node работает
  с упакованными ciphertext. DeviceRoot — локальный secret, не сетевая Device.
  V3 Device gateway — временный migration path, не скрытый итоговый fallback.
- Направленные локальные маршруты; не придумывать глобальный Account transport ID.
  Transit не использует Account E2EE keys. DHT вне scope. Не заявлять анонимность,
  PCS/PFS/PQ или full DONE без соответствующей приёмки.
- Сохранять Root, Node/Account identities, history, keys, encrypted DB и ownership.
  Не reset storage ради PASS. Destructive/fault сценарии только synthetic profiles.
- Production/deploy/сброс пользовательских данных в этой native работе не
  выполняются. Source/context sync не переносит EMS/PWA/backend runtime.
  Фактический опубликованный checkpoint — [FORGE_SYNC.md](FORGE_SYNC.md).

## 2. Независимо принятые результаты и их точный scope

Все ссылки ниже описывают собственные source/binary hashes и ограничения.
Это не новый full exact-HEAD PASS и не приёмка трёх готовых приложений.

| Область | Проверенный результат | Evidence / граница |
| --- | --- | --- |
| Credentials/browser | Versioned Root wrap/legacy migration, тот же Root/Account/original Saved, cancel/retry; Account legacy Argon2d type0 сохранён для identity | [Retained migration](docs/native/2026-10-20/root-s01-retained-migration.json), [worker cancel](docs/native/2026-10-20/root-s01-worker-cancel.json). Hardware/full crash matrix отдельно. |
| Browser UI fixes | Stored Node URL treated as data; chat delete× confirmation/cancel works; history password set/wrong/correct/remove, denied microphone/camera preserve controls and original row | [URL](docs/native/2026-10-20/root-node-url-xss-green.json), [chat](docs/native/2026-10-20/root-chat-delegation-green.json), [history](docs/native/2026-10-20/root-browser-history-controls.json), [media denied](docs/native/2026-10-20/root-browser-media-denied.json). Не all-controls/media positive PASS. |
| Native Node | Qt/QuickJS actor, actual default22 Python interop, NodeID retained, second owner refused, SIGTERM/SIGINT exit0 | [Actor](docs/native/2026-10-20/root-native-actor-interop.json). |
| Inbox/queues | Encrypted SQLite Inbox/CAS/quota/recovery, unchanged JS consumer/70 IDB differential ops; real opaque delivery, recipient SIGKILL/reopen, atomic app consumption/idempotence | [Inbox](docs/native/2026-10-20/root-native-inbox-verification.json), [delivery](docs/native/2026-10-20/root-native-delivery-consumption.json). Не новый network custody ACK. |
| Foreign transit | Actual two Python peers only through native middle, no Account/owner registration, hop rewrite/duplicate/expiry; immutable a0f54a9 Node | [Transit](docs/native/2026-10-20/root-native-foreign-transit.json). NAT/alternate-route failover отдельно. |
| Fresh zero-Account transit | Root53718 PASS: profile.create + node.enable, zeroAccounts/no import/login, two actual default22 Python peers only through native child; foreign discovery/DATA2→1/hop rewrite/expiry; client detach preserves Node, Rootlock stops | [Proof](docs/native/2026-10-20/root-fresh-zero-account-transit.json). Immutableb300a25 fixture/ca849host/64eNode,1145files/7libs exact. Configured WS loopback peers; NAT/self-organization NOT RUN. |
| Account retained data | Secure-only registry, тот же Account public ID, original Saved1→native write2, logout/relogin, source owning export unchanged | [Account](docs/native/2026-10-20/root-native-account-retained.json). |
| Initial import recovery | Atomic staged publish/retry, crash before/after stage/publish, concurrent publisher, no overwrite of accepted DB/keys | [Import](docs/native/2026-10-20/root-account-import-recovery.json). Это initial import, не full N4. |
| Resident host | Separate credential/Account process, UI death/Account logout preserve Node; Root lock stops Node; Account cancel preserves unlocked Root/Node | [Host](docs/native/2026-10-20/root-resident-credential-host.json), [resident UI](docs/native/2026-10-20/root-desktop-resident-ui.json). |
| Ordinary private pairing API | Root62234 PASS: freshRoot/Account2, no injectedcontacts/routes, signedRequest/Accept/Confirm, actualnativeKyber,37forwards; bilateralhistory2 +bothrelogin2 | [Proof](docs/native/2026-10-20/root-native-private-pairing.json).1177files/30runtimeentries exact; sourceintegrated006814a–a1bc16c. UI pairing/NAT/publiccontacts NOT RUN; manualfirstsend retry limitation below. |
| Actual remote E2EE | Immutable283ba51 integrated3e3e845:2245 archived files/18 libs exact, fresh signed pairs, nativeNodes→Python transit20forwards. Recipient Account exit73 after durable history before consume; before/replay/reopen1, both identities/history retained | [Remote Account](docs/native/2026-10-20/root-native-remote-account.json). Known synthetic signed pair/scoped grants; ordinary UI pairing NOT RUN. Node binary explicitly older a0f54a9. |
| Local capability lease | Runtime64e6933 + test875c679: real TTL10→30, past original expiry same token/socket/ACTIVE tuple, initialized Node, fresh auth | [Lease](docs/native/2026-10-20/root-native-capability-lease.json). Mint deliberately rotates/drops old contexts; не использовать вместо lease extension. |
| Host crash/recovery | Immutablea52e9f5, root44213 exit0:183source/19artifact/7libs exact; SIGKILL host/Node lease EOF; sameRoot/Node/gens1,3,5,7/Saved2; authenticated floor merge; cancel stops verified suspended oldchild. Process/cancel/logout/reopen/ACTIVE grant lease PASS | [Recovery](docs/native/2026-10-20/root-resident-host-recovery.json). Integrated f8b17d2/1a5f179/87fc172. Не full N4; pin Account resources older remote integration. |
| Fresh setup | Immutableca849fd root65965/54456 PASS:187source/27artifact/7libs exact; Root-only/zeroAccounts, optional compatible Account, cancellation, duplicates refuse overwrite, Saved/reopen/missing-key refusal; original JS/WASM Root+registry interop | [Fresh](docs/native/2026-10-20/root-fresh-root-account.json). Integrated1930b80; Root fresh transit accepted separately above; fresh UI still open. |
| Desktop Account controls | Actual Widgets chooser/import/PIN/Account cancel/wrong/busy/correct/Saved/reopen on owning copy. Clipboard test-only correction33a6273 root20183 PASS3/0/22.644s, unchanged pinned product | [Chooser retest](docs/native/2026-10-20/root-desktop-chooser-retest.json). Visible Node controls ещё не root PASS. |
| Telegram Desktop first layout | Actual root97893 XCB UI PASS4/0/5609ms,242source/8artifacts/runtime hashes verified; actual synthetic Saved screenshot inspected | [Proof](docs/native/2026-10-20/root-desktop-telegram-ui.json), [preview](docs/native/2026-10-20/desktop-telegram-preview.png). Source7aaccb3; design PARTIAL, header border fix pending; no Android/Windows/full UI/remote acceptance. |
| Desktop fresh setup | Root actual Qt mouse/key controls PASS offscreen3035ms and XCB/Xvfb4076ms; Createprofile Cancel/empty/mismatch/valid, optionalAccount Cancel, CreateAccount/signin/Saved/windowreopen/signout | [Fresh UI](docs/native/2026-10-20/root-desktop-fresh-ui.json).241source/8artifacts exact. Sourceeea5c69; no Node-button/remote/Windows acceptance. |
| Android package/UI | ARM64 package/signature/16K ELF inspection; actual x86 API35 KVM install/launch, Stop/compose/Send disabled when off, Details Close/Back, background/resume | [Package](docs/native/2026-10-20/root-android-package-inspection.json), [actual UI retest](docs/native/2026-10-20/root-android-kvm-launcher-retest.json). Node service/Account/UI/full app acceptance ещё нет. |

## 3. Текущие FAIL, неподтверждённые причины и незавершённые checkpoints

- **Host initial bootstrap observation:** root405263e first node.enable failed
  NODE_BOOTSTRAP_FAILED before intended crash. Diagnostic-only a52e9f5 successor
  later passed all three independent fixtures. Причина первого FAIL не установлена;
  не выдавать последующий PASS за доказательство устранения причины. Новые fixed
  codes distinguish READ_TIMEOUT/CHILD_CLOSED/WRITE_FAILED/FRAME/RESPONSE_INVALID;
  deadlines unchanged. Failed synthetic profiles/logs now retained privately.
- **Renewal history:** original6a5b50a was integratedbf77a5a then REVERTEDabf1c16:
  MintCapability silently dropped old owner contexts, initial nodeRunning-only
  test was insufficient. Corrected set now integratedf8b17d2+1a5f179+87fc172,
  uses explicit64e private lease extension and actual ACTIVE-grant checks.
- **Desktop Node controls:** cf41678 author synthetic actual-button PASS27.696s.
  Root43987 FAIL at chooser canonical path then240s modal timeout. Test-only
 33a6273 fixes paste/cleanup, Account-only independent retest passes. Full retained
  optional Node gate still240s timeout after chooser; no root Node-button PASS.
  Platform adds stage diagnostics before another run. Do not claim timeout proves
  Node provisioning failed without stage evidence.
- **Android service first install:** KVM run39439689745 actual launcher fix2b293db
  PASS, then scoped first-install TimeoutException. Exact Qt6.12 source shows
  QAndroidService startup singleShot(0) releases Java service semaphore; old entry
  blocked eventloop on condition variable. Fix9988c73 pumps bounded QEventLoop,
  exact x86 native compile PASS, original15s unchanged. Actual KVM retest
 39443522111 still FAIL first-install-bootstrap-read TimeoutException: Binder alive,
 nativeExited=false, serviceState STARTING. [Retest](docs/native/2026-10-20/root-android-service-bootstrap-retest.json).
 Timer fix is not runtime-accepted; platform investigates pre-JNI startup stage.
  Diagnostic471ca1c distinguishes activity/binder/bootstrap phases and fixed states.
 c145656/5d1d2ce actual run39446127764: all325 source hashes match4bdf1da,
 APK hash verified; same timeout with nativeStartupStages=[] (no ENTRY observed).
 [Run8 proof](docs/native/2026-10-20/root-android-empty-entry-retest.json).
 No specific loader cause established.8bd1c88/f639999 bounded Qt-loader reason
 collector actual ec66run39449711991 now terminal FAIL: event
 NATIVE_LIBRARY_LOAD_FAILED, missingLibraries=[], no ENTRY. Root exact source/APK
 verified. [Loader reason](docs/native/2026-10-20/root-android-loader-reason.json).
 Specific load cause unresolved; runtime agent investigates read-only while
 platform implements requested Telegram UI.

- **Windows:** actual run39443521913 source9988c73 exact merge tree confirmed:
  all75 Desktop/host/UI-test targets compiled and linked. desktop-controls then
  failed0.06s with empty output before QtTest banner. Cause unknown; no UI action
  or package acceptance. [Attempt](docs/native/2026-10-20/root-windows-compile-launch-attempt.json).
 10c5743 adds bounded direct exitcode/DLL/plugin diagnostics +always-upload logs;
 actual22a run39447632824 terminal same CTest FAIL0.05s; direct diagnostic reports
 EXITED0 with empty stdout/stderr and no QtTest banner. No cause established.
 [Artifact inspection](docs/native/2026-10-20/root-windows-empty-direct-diagnosis.json).
 Broker now owns Windows build.ps1/diagnose-startup.ps1. Standalone Account/Node suites and Windows package
 not reached. Earlier compiler/OpenSSL/include fixes have passed this boundary.
- **Long certificate retry/recipient Node restart accepted:**3cf41d9 stable expiresAt
  +9e23a60 fixture independently passed root54951 exit0,31forwards, lost accepted
  submit reply→samejobID/expiry; Account73→NodeSIGKILL→same profile/key/bundle,
  reconnect/history1 before/replay/reopen, both owners retained.2247files/19libs
  exact, same retained long-certificate Account fixture as earlier root attempt.
  Integrated f187474/9308218. [Proof](docs/native/2026-10-20/root-native-account-retry-node-restart.json).
  Earlier12040 native-authorize180s FAIL remains an unexplained admission
  observation; quiet subsequent PASS does not prove its cause. [FAIL](docs/native/2026-10-20/root-native-account-retry-attempt.json).
  Known signed pairs/scoped grants/old a0f Node; not UI pairing or full N4.
- **First remote message fixed at component scope:** source31c5aa4 and focused
 followup integrated after root56828 actual PASS: send once before other ready,
 accepted pending/history visible, Account logout/relogin + owner SIGKILL/same
 identity reopen, automatic bilateral delivery/history2/relogin2 without retry.
 [Actual proof](docs/native/2026-10-20/root-native-first-send.json). Immutable01
 1183files/30runtime exact,38forwards, activation146.05/72.42s under unchanged150s.
 Followup02 1187/30 exact, strict transient handoff and actual retained Account
 test62090 PASS; [proof](docs/native/2026-10-20/root-first-send-transient-retest.json).
 Actual Telegram fork UI not yet accepted; public/NAT/fullN4 remain separate.

- Android ordinaryAccount UI source d0f6990 was published177; cc0fe09/aadace6
  Telegram layout+matchingnavCI newer than published85 snapshot. Immutablev6
 302source at aadace6 is building8597; actual runtime not accepted. Native pins
 predate newly integrated privatepairing and require coherent provenance.

## 4. Source publication, environments и активные проверки

Latest published GitHub snapshot **0783fd0440767e76433c2902b5c8c80a918f0883** is
exact local **e00db0abb1baddc4c18bfd2ec6dd757c398f3d5e** tree
**5ec547e905de8c901645ce6eab4be278f2525188**. create_tree exact + git ls-remote
verified. Actual Linux run39466512625/job118779217412 TERMINAL FAIL at
owned dependencies: exact libprotobuf-dev=3.21.12-8.2ubuntu0.4 absent from apt
index (agent artifact12285456677; no full application compile). No silent version
fallback. Agent investigates official same-bit archive URL/hash. Next automatic
Linux run39467132097 on274419 is IN_PROGRESS; observe same job, no timeout rerun.
Old Windows39466512564/Android39466512504 and newer39467132094/39467131993
are intermediate harnesses, not actual Telegram fork GUI acceptance.
Platform followup e740454 corrects checkout cache and includes owned UI paths/MIT
notices. Root independently reconstructed33files from both patches;
[proof](docs/native/2026-10-20/root-desktop-owned-profile-source.json).
Local build13001 keeps earlier32file source; no mutation under live compiler,
local13001 terminalFAIL240/822: owned jpeglib.h cannot find multiarchjconfig.h.
Platform targeted include fix in progress; old32source/cache/log preserved. No new screenshot exists yet.
Latest published source includes Android actual KVM workflow e00db0a and Linux
same-version official pool downloader02250ac. Root compared all131 pins unchanged,
independently downloaded libprotobuf-dev1413370bytes/SHAacc0ec3dee7e496451656170e0210c56efd49ffcff243df8ce9893aa55f44e24.
New actual Android39467452315 and Linux39467452496 IN_PROGRESS. Old harness
Windows39467452592/Android39467452074 remain distinct. Do not rerun from timeouts.
Android incremental source e89d376 resumed under durable supervisor1120853,
client1120881; root independently /proc verified start tokens3568783/3568824.
State private/telegram-android-assemble-04-state.json terminalFAIL EXIT1: upstream
WamrCoreBackend.h missing wasm_export.h. Root verified state/log and both PIDs
absent. Exact WAMR gitlink required initialization added0f7c79e, all19pins unchanged;
root prepare8tests PASS3.405s. New durable assemble05 supervisor1129220/start3598517,
client1129248/start3598533 authorLIVE, same source/cache. No final APK yet.
Branch `codex/native-clients-ci-20261020`, draft
[PR8](https://github.com/Seriy615/D-MASH/pull/8). Full fork applications not
accepted; later source/docs/WIP are not implicitly published. See FORGE_SYNC.

Actual source pins/licenses independently verified; Desktop c6db2fa27files and
Android70f5513 two-patch21files reconstructed/hashverified by root. Actual Android
Java43687 terminal0 authorPASS8m42s: root verified13files/3compilerQtjars,
21patchedsources and14037classarchiveentries, inspected original Activities and
both QtServiceBase subclasses. [Artifact evidence](docs/native/2026-10-20/root-android-fork-java-inspection.json).
No independentGradlererun/APK/service/UI/no-egress acceptance. Coherent Android
core source139795 build10125 terminal0 (61targets), Qt aux deployment terminal0; root359source/40artifact hashes verified, bothELF64x86_64, pending_sends/pairing_host included. [Proof](docs/native/2026-10-20/root-android-coherent-core-inspection.json). No APK/service/runtime yet. Actual Desktopfull configure
reached tde2e/tg_owt; both configurePASS, tde2e build83170 terminal0,124targets/installPASS; selectedmainapp objects13001 nowactive after GIR/pkg-config environment fixes. tg_owt archives notyetbuilt. Original media/calls retained; no fullappcompile/render yet.

Windows4929 run39466512564 terminalFAIL is now root-inspected: retainedAppLocalKey
first-key-open PROFILE_KEY_PUBLISH_WIN32:32 (sharing violation), ZIP58275d7f... .
Fix1b66709 uses Qt-owned no-overwrite rename and keeps published key; Windows
runtime retest pending. [Evidence](docs/native/2026-10-20/root-windows-key-sharing-failure.json).
Desktop selected-session source bc76ed0 independently reconstructed all34files/
3patches; production adapter+projection frozen components root2PASS,11pin files
hashverified. [Evidence](docs/native/2026-10-20/root-desktop-binding-adapter.json).
Actual two windows/render/chat NOT_RUN; Android adapter separately pending.

Latest aa30 Windows39460137863/job118757157412 terminalFAIL; rootartifact12282556614
now pinpoints retainedAppLocalKey caughtunhandledexception (1PASS1FAIL4ms), CTest
0.05s. Exactstage/causeunknown; boundeddiagnostics assignedbroker. [Proof](docs/native/2026-10-20/root-windows-retained-key-failure.json).
Latest aa30 Android39460138103 terminalFAIL in oldharness visibleUI01-messenger-ready,
before servicegate; no inference that oldQtloader cause fixed. Actualfork separate.
Earlier Windows directQtTest3PASS and fullCTestFAIL remain component evidence;
existing native CI uses intermediate harnesses, not finalforkapp acceptance.
Android oldQtloader cause remains unresolved. No source publication is deployment.

Root reference runner **20832 terminal0 PASS**, immutable reference-3a72492:
Python3.12.3 + requirements-test.txt, Node24.19.0; 303backend +22Origin tests,
162JS suites, zero failed suites. Sourcearchive8dc15defa671415f52d2d95f07956de6da529c59c3873d618263f5e8ad111b97.
[Exact evidence](docs/native/2026-10-20/root-reference-3a72492.json). Frozen3a72492
UNIT/component runner only; not dirtyHEAD/fullfork/app/browser acceptance.
Reverse author62742 terminal0 PASS42forwards; root independent53677 terminal0 PASS26forwards, activation38.449/24.267s. [Actual root proof](docs/native/2026-10-20/root-browser-native-interop.json). Mesh quiet; platform one-worker builds released.

Toolchains/private pins: `/home/jcode/.cache/dmash-native-20261020`.
Node `/home/jcode/.cache/dmash-tools/node-v24.19.0-linux-x64/bin/node`24.19.0;
Python `/home/jcode/.cache/dmash-tools/python-s03-20261020/bin/python`3.12.
Reference full runner: `.venv/bin/python tools/test_all.py`, requirements-test.txt.
Frozen3a72492 full runner PASS; no dirtyHEAD/fullfork app PASS. Focused checks supplement actual UI/network.

Local Android software AVD failed OS boot watchdog before APK install and was
intentionally stopped; synthetic AVD data retained. Do not restart it merely
because an old observation timed out. Actual runtime route is GitHub KVM.
Owning browser CLI `dmash-root-retained`, profile
`/home/jcode/.cache/dmash-qa-20261020/root-retained-profile`, loopback9181,
source004fa12/.43, SW/external HTTP/WS blocked. Revalidate live page/process before
use. Credentials/access receipts/exports0600 are private, never print or commit.
Latest owning backup root-after-history-qa.json; complete native import input
root-complete-profile-43.json SHA7f35126664d3f4828b9ed5e93e55eb27da70e5d5dc7f38cfd9af7448609ce9b6.
Original Saved row preserved. Operator previously entered emergency combination
in synthetic QA; exact owning backup restore/origin verification and subsequent
normal unlock/login recorded in BROWSER_QA. No user/production data touched.

## 5. Команда и ближайшая работа

Root — оркестратор/интегратор/тестировщик; реализацию выполняют агенты.
Все три известны с явным gpt-6.1-sol; разрешены только gpt-6.1-sol/gpt-6-luna.
Не возобновлять старых неизвестных агентов. Source pins не являются backup
runtime DB/keys. Не reset и не очищать пользовательские данные ради PASS.

- **broker_store_sol:** actual Telegram Android fork pinned0aae9598. Java03
  full original module43687 terminal0,8m42s/137tasks, fork16b2cbf; exported
  two-patch recipe integrated70f5513. Root reconstructed21files from upstream+
  bothpatches, all hashes match; prepare8tests PASS. [Source proof](docs/native/2026-10-20/root-android-fork-source-roundtrip.json).
  Patch003 integratedca2c128: retained uncertain-send IDs/text, Account-local
  callback fences, RAM drafts, DNS/proxy/update guards; fullJava65110 terminal0
  authorPASS8m14s. Root25filethreepatchroundtrip +actualJavaunit11493 PASS3.769s;
  [proof](docs/native/2026-10-20/root-android-pending-send-unit.json). ServerAccount
  contextbinding implemented/root process PASS separately below; Android frontend
  attach and enqueue guards staged separately. Six-patch recipe integratedcd7cc30.
  Actual APK83912 exited143 after346 JNI entries: agent verified exact Gradle/
  Ninja processes exited after client disconnect. No C++ failure or APK result.
  Incremental resume in same source/cache under durable supervisor authorized;
  actual fork KVM CI draft is next route to genuine screenshots. Local /dev/kvm
  and attached adb device absent. No APK/service/UI/no-egress claim. Coherent native source
 139795f frozen, native compile released after root53677 terminal. Old v6 jars
  were compiler dependencies only, not a coherent runtime acceptance.
- **native_platforms_sol:** actual Telegram Desktop pinned86262333. Sourcec6db2fa
  includes original Intro/Main::Account/DataSession/History/primaryComposer,
  sameoperation until accepted, idle disconnect invalidation/epoch fences and
  reproducible preflight. Root independently reconstructs27files from upstream+
  patch, all hashes match. [Proof](docs/native/2026-10-20/root-desktop-fork-source-roundtrip.json).
  Full selectedappconfigure44697 PASS; actualmainapp objects13001 -j1 nice10
  nowactive (originalUI/codegen/PCH+ModelBridge/Intro/HistoryWidget). No binary/link/
  render claim; tg_owt archives stillunbuilt. tde2e83170 terminal0 all124/install
  PASS; projectionCTest1/1 authorPASS (validupstreamClientMsgByIndex, sameop IDs).
  Projection/storage fences integrated0917d37; root32file patch reconstruction and
  frozen production projection test PASS, not full app compile or UI acceptance. Owned deps fd197cd
  tracked; cleanmachinefullrecipe execution NOT_RUN.
  Fresh Intro create/chooser, full persistence fencing and all platform/UI
  acceptance remain open. Root permits low-worker compile after mesh finishes.
- **native_runtime_sol:** private pairing/durable first-send already integrated
  and root accepted. Browser/native helper/proof series integrated8ed2e46–8dd090d;
  sameimmutable6e96pin1188files/30runtime/2browserfiles +48servedJS/WASM root
  hashverified. Author default67599/reverse62742 terminal0; root53677 terminal0
  actual default direction PASS26forwards/history2/relogin. SW0/component HTML,
  Core.launchWorkspace presentation stub; no ordinaryUI/.45/deployed/NAT claim.
  Account-context fix integrated0288bff/a205017. Root42502 actual two-client IPC
  and45778 actual worker regression terminal0 PASS: stale/unbound reads/writes/
  logout/sync/pairing/cancel refused, explicit expected-Account attach, same-Account
  relogin epoch rejection, histories retained after restart. [Evidence](docs/native/2026-10-20/root-account-client-binding.json).
  Actual fork frontend attach/enqueue/callback guards and visible two-window flows
  remain NOT RUN; same-socket queued old intent needs frontend generation checks.
  Public work stays isolated: contract9563459/store947faff root36191 unitPASS,
  [proof](docs/native/2026-10-20/root-public-store-parity.json); typedports/profile/
  credential/Account publicWIP builds18799/18660 terminal0. Offline79354 FAIL
  at public→pause→private start: NODE_BOOTSTRAP_READ_TIMEOUT under unchanged5s
  deadline. Earlier neutral registration/reattach/profile validation/public reopen
  phases passed; not full profile acceptance. Same failed profile retained; exact
  owner/child PIDs and /proc scan confirm stopped before any retry. Bounded startup/
  diagnostic probe88756 terminal1: same original profile, public3697ms→pause82ms→
  private4025ms PASS→pause92ms→returnpublic5773ms READ_TIMEOUT. Failed child
  READY5525ms after parent leaseclose5054ms; child exit confirmed5665ms/noKill,
  zero profile processes remain. Native parity2741/3176/2935ms; JS stamps reflect
  queued delivery and cannot attribute remaining time. Emission timestamps next;
  no second probe/mesh authorized, deadlines/storage/identity unchanged.
  Do not advertise public or
  bump metadata untilcoherenttests. No newmesh whileplatformcompiles.
- **Root:** actual fork source review and independent integration/acceptance;
  frozen3a reference full runner PASS303backend/22Origin/162JS. Current MIT text/
  GPL scope formalizede6f1c13. Known source findings assigned in BROWSER_QA;
  no full fork app or exact dirtyHEAD release claim. Actual Windows Telegram UI
  uses upstream MSVC/clang-cl while old core CI is MinGW; final package needs
  separate UI/core Qt DLL/plugin directories over IPC, not shared Qt binaries.
  No production/deploy/EMS/
  backend migration or user-storage reset.

Main remaining work: actually build/render/test original Telegram forks on Android,
Windows and Linux with our real Account/Node, ordinary pairing/chat/menus/error/
cancel/reopen/notifications; full UI inventory; public contacts; full N4 mailbox/
state recovery; selforganization/NAT/direct/relay mobility; buffered encrypted
files and flexible policies; complete packaging/licenses/docs/threat model.
DHT stays outside scope. Do not replace these goals with a green component suite.

## 6. Документация и отчётность

[Implementation delta](docs/native/2026-10-20/CURRENT_IMPLEMENTATION_DELTA.md),
[threat model](docs/native/2026-10-20/THREAT_MODEL.md),
[frozen audit](docs/audits/2026-10-20/README.md),
[backlog](docs/audits/2026-10-20/IMPLEMENTATION_BACKLOG.md),
[platform targets](docs/native/2026-10-20/TARGETS.md).
Документы различают IMPLEMENTED/PARTIAL/PLANNED, UNIT/PROCESS/BROWSER/DEPLOYED,
historical evidence и новый exact source PASS. Runtime DB/keys/ownership backup
и rollback не заменяются Git checkout. Лицензии vendor/старого Kyber/WABT/Qt
не превращать автоматически в MIT; Telegram GPL заимствования учитывать отдельно.

## 7. Обязательный UI-аудит и правила приёмки

Всё проверять реальными browser/UI actions и видимым результатом. Перед новой
разработкой инвентаризировать и нажать каждую кнопку/меню/modal control, включая
error/loading/disabled/cancel. [BROWSER_QA.md](BROWSER_QA.md) содержит inventory,
PASS/FAIL/NOT RUN, page/SW version, reproduction/evidence, bug owner/fix/retest.
Historical178 control classes:67 scoped PASS/4FAIL/107 NOT RUN; новые узкие retests
не превращают эту матрицу в all-controls PASS.

Обязательный обход: calculator setup/unlock/master/wipe (wipe только fresh test),
Account create/login/logout/switch/recovery; navigation/settings; Node request/
connect/disconnect/password; QR create/scan/import; private/public route create/
disable/delete; Request/Accept/Confirm/pending cards; все chat SEND/history/delete/
read и Saved/history password; voice/circle record/SEND/cancel/playback/retry/
download; calls start/accept/decline/hangup/audio/video; files request/consent/
progress/cancel/complete; notifications и все найденные дополнительные controls.

Найденные баги назначать агентам, исправлять и повторно проверять на интеграции.
Проверять два Accounts, public/private, offline/locked/reconnect, denied permissions,
stale SW/mobile limits. Console/Core calls/RTC stats/unit tests дополняют клики,
но не заменяют их. Physical phone/WebAuthn отмечать NOT RUN без реального устройства.
Browser-first аудит не отменяет Node архитектуру и N0–N8. Local done агента не
закрывает общую цель; не объявлять full DONE по отдельному зелёному тесту.

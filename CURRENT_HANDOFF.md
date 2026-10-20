# D-MASH — текущий хендофф

**20 октября 2026 UTC. Цель ACTIVE. Android, Windows и Linux приложения НЕ ГОТОВЫ.**

Последнее указание пользователя: «аккуратно думай не сильно о кибербезе».
Приоритет — обычная переписка, автономная фоновая Node, простой UI и сохранность
данных. Повторное явное требование пользователя: «я просил дизайн из тг взять».
Telegram Desktop и Telegram Android из исходно указанных репозиториев — образцы
обоих интерфейсов. Текущий произвольный teal/Widgets экран — промежуточный,
НЕ приёмка дизайна; воспроизвести Telegram компоновку/navigation/chatlist/chat/
composer/settings, проверять реальными UI actions и сравнением скриншотов. Исправлять подтверждённые ошибки; не добавлять гипотетические проверки
и пользовательские церемонии. Этот файл — единственная текущая сводка.
Исторические checkpoints/deployments доступны в Git и docs/archive; они не
задают текущие SHA, указания или критерии DONE.

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
| Actual remote E2EE | Immutable283ba51 integrated3e3e845:2245 archived files/18 libs exact, fresh signed pairs, nativeNodes→Python transit20forwards. Recipient Account exit73 after durable history before consume; before/replay/reopen1, both identities/history retained | [Remote Account](docs/native/2026-10-20/root-native-remote-account.json). Known synthetic signed pair/scoped grants; ordinary UI pairing NOT RUN. Node binary explicitly older a0f54a9. |
| Local capability lease | Runtime64e6933 + test875c679: real TTL10→30, past original expiry same token/socket/ACTIVE tuple, initialized Node, fresh auth | [Lease](docs/native/2026-10-20/root-native-capability-lease.json). Mint deliberately rotates/drops old contexts; не использовать вместо lease extension. |
| Host crash/recovery | Immutablea52e9f5, root44213 exit0:183source/19artifact/7libs exact; SIGKILL host/Node lease EOF; sameRoot/Node/gens1,3,5,7/Saved2; authenticated floor merge; cancel stops verified suspended oldchild. Process/cancel/logout/reopen/ACTIVE grant lease PASS | [Recovery](docs/native/2026-10-20/root-resident-host-recovery.json). Integrated f8b17d2/1a5f179/87fc172. Не full N4; pin Account resources older remote integration. |
| Fresh setup | Immutableca849fd root65965/54456 PASS:187source/27artifact/7libs exact; Root-only/zeroAccounts, optional compatible Account, cancellation, duplicates refuse overwrite, Saved/reopen/missing-key refusal; original JS/WASM Root+registry interop | [Fresh](docs/native/2026-10-20/root-fresh-root-account.json). Integrated1930b80; Root fresh transit accepted separately above; fresh UI still open. |
| Desktop Account controls | Actual Widgets chooser/import/PIN/Account cancel/wrong/busy/correct/Saved/reopen on owning copy. Clipboard test-only correction33a6273 root20183 PASS3/0/22.644s, unchanged pinned product | [Chooser retest](docs/native/2026-10-20/root-desktop-chooser-retest.json). Visible Node controls ещё не root PASS. |
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
 collector published for next actual runner; includes QtLoader warning severity.

- **Windows:** actual run39443521913 source9988c73 exact merge tree confirmed:
  all75 Desktop/host/UI-test targets compiled and linked. desktop-controls then
  failed0.06s with empty output before QtTest banner. Cause unknown; no UI action
  or package acceptance. [Attempt](docs/native/2026-10-20/root-windows-compile-launch-attempt.json).
 10c5743 adds bounded direct exitcode/DLL/plugin diagnostics +always-upload logs;
 next actual runner required. Standalone Account/Node suites and Windows package
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
- Android Account Views/credential service remain platform-owned WIP, not the
  published launcher. Current build checkpoints may predate accepted host/Account;
  require coherent frozen source/binary/resource provenance before acceptance.

## 4. Source publication, environments и активные проверки

Latest published GitHub snapshot **ec66d1142cdc94a8859cec4e29f6b72c4baef45b** is
exact local **f63999927916daee7fd7c7f2baae4e55bf46fb61** tree
**7223bc5867c8df77abdc7e16cec1a567fcbcb8b8**. create_tree exact + git ls-remote
verified. Branch `codex/native-clients-ci-20261020`, draft
[PR8](https://github.com/Seriy615/D-MASH/pull/8), attached to task.
Later source/docs and live platform WIP are not implicitly published.
See [FORGE_SYNC.md](FORGE_SYNC.md). No deployment or runtime-state backup.

Last actual REST check:22a snapshot Android39447633575/job118713660813 LIVE
(scoped emulator service test); Windows39447632824/job118713657263 LIVE.
4ed Android39446127764 and Windows39446127350 terminal FAIL. New ec66 snapshot
contains loader diagnosis/scope changes; new run outcome not yet inspected.
Use fresh public REST Cache-Control:no-cache: connector statuses may be stale.
Transient log failure does not prove a process/job stopped; poll the same handle.

Toolchains/private pins: `/home/jcode/.cache/dmash-native-20261020`.
Node `/home/jcode/.cache/dmash-tools/node-v24.19.0-linux-x64/bin/node`24.19.0;
Python `/home/jcode/.cache/dmash-tools/python-s03-20261020/bin/python`3.12.
Reference full runner: `.venv/bin/python tools/test_all.py`, requirements-test.txt.
No fresh full exact-HEAD runner PASS. Focused checks supplement actual UI/network.

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

Пользователь требует delegation. Root — оркестратор/интегратор/тестировщик;
реализацию выполняют агенты с разделённым владением. Все три текущих агента
известно созданы с явным gpt-6.1-sol. Разрешены только gpt-6.1-sol/gpt-6-luna;
новых создавать с явной моделью, старых неизвестной модели не возобновлять.

- **broker_store_sol:** isolated credential-host worktree. Accepted recovery
  integrated. Fresh Root-only/optional Account1930b80 independently accepted. Next isolated
  transport-only node.pause/resume preserves unlocked Root/Account/queued jobs;
  current node.disable=fullRootlock unchanged until coherent UI migration.
- **native_runtime_sol:** native actor/localIPC, isolated remote Account worktree,
  Android CI diagnostics. 3cf/9e independent parent54951 PASS, source integratedf187474/9308218. Diagnose
  admission failure using retained metadata, no cause guess. Fresh foreign transit fixture accepted independently, integrated05dd2cc. Now
  ordinary private pairing/contact DTOs + existing bootstrap runtime/dispatcher
  via separate encrypted SQLite; optional trusted store/KEM +private-v1 seams
  isolated f50e82c UNIT only, not shared yet; actual native pairing pending.
  Platform now owns Android CI UI/instrumentation files.
- **native_platforms_sol:** PRIORITY: Telegram Desktop/Android design requirement above;
  inspect/pin original reference source, implement both native client layouts,
  move daemon technical controls into menu/settings. Existing functional UI tests
  do not accept current arbitrary layout as requested design. Desktop Node-control stage diagnostics, Android normal
  Views/credential service and Windows compile/runtime fixes.9988 entry published.
  Coherent Androidv5 frozen on4bdf1da includes fresh1930/f187/host87 +ownedUIWIP;
  native4448/package65976 both exit0. Immutable android-account-v5 root verified329source/7artifact hashes, APK signature/ZIP16K/18ELF16K. [Package only](docs/native/2026-10-20/root-android-account-v5-package.json); runtime NOT RUN. Desktop freshCreate build57970 exit0, sourceeea5c69 root fresh UI accepted (table above). Next CI must exercise
  ordinary Createprofile/optionalAccount/Saved UI, technical Node checks via
  explicit NodeTools screen. Preserve strict assertions. Next freeze includes distinct owner
  epoch vs transport generation, real child-exit recovery and lease-extension
  hooks. Do not package unaccepted captured WIP as final app.
- **Root:** inspect current CI actual outcomes/artifacts, independently
  test immutable app/UI/runtime checkpoints, integrate accepted source, update this
  one current summary and QA. Avoid concurrent heavy mesh fixtures on2CPU; do not
  change protocol work/deadlines to get PASS.

Main remaining product work: fresh usable setup; contacts/private+public pairing,
ordinary bilateral remote chat in both UIs; Node controls/policies with transport
pause distinct from full Root lock; complete N4 state/mailbox migration/recovery;
NAT/direct/relay mobility, encrypted buffered files, configurable policies and full
three-platform packaging/lifecycle acceptance. DHT remains out of scope.

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

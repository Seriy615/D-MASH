# Browser-first QA — текущий аудит Forge

Требование пользователя от 8 октября 2026: всё тестировать браузером; перед
новой разработкой проверить каждую кнопку, найти баги, назначить агентам,
исправить и провести повторную приёмку. Тимлид/оркестратор сам отвечает за
интегрированный результат. Этот файл — журнал и начальная матрица, не утверждение,
что полный обход UI уже выполнен.

## Актуальный release checkpoint

PWA **fd2a7505ba7325ee0d47e38cb2cfc8271cbfc0c1**, `.28`, опубликована на EMS;
backend остаётся **3c513601ef3990b6514e247d879324b7b72da494**. Exact source
**217/217**, missing/changed []; source branch merge `f0af5b1` exact UNIT281
backend +11 Origin +84 JS PASS. Independent deployed Chromium fresh two-profile
PUBLIC Request/Accept/Confirm, key exchange, messages and FlipLock: **16/16 PASS**,
page+SW обоих profiles `.28`, 136 loaded sources exact SHA, errors [], exit0.
Immediate key feedback 157 ms. Перед deploy первый immutable `.28` public run
завис на key completion с DNSS pending после успешных Request/Accept/Confirm;
второй fresh source-overlay run 16/16 PASS, deployed fresh run 16/16 PASS.
`ROUTE-READY-01` остаётся OPEN, single success не доказывает отсутствие гонки.
Supplemental deployed owner-conflict synthetic
incoming/send-failure UI **7/7 PASS**, page `.28`, SW BLOCKED; no remote delivery
claim. Physical mobile orientation NOT RUN. `.27` baseline 16/16 и `.26` baseline
13/13 PASS и [manifest](docs/evidence/2026-10-08/qa-release26-manifest.json)
остаются historical evidence, не текущим release. [Deployed `.28` browser report](docs/evidence/2026-10-08/qa-ui-hotfix-deployed28.json),
[owner fixture](docs/evidence/2026-10-08/qa-contact-owner-deployed28-summary.json),
[deployed `.27` browser report](docs/evidence/2026-10-08/qa-ui-hotfix-deployed27.json)
и [sanitized live pairing note](docs/evidence/2026-10-08/qa-live-pair-deployed26-sanitized.md).
Deployed readiness CDP logpoints may affect timing; difficulty22 observed, duplicate
proof work remains a hypothesis until exactresource equality is observed. Previous
intermittent timeout evidence is retained, not overwritten by this successful run.
Node runtime consistent backup6SQLite checksPASS,4keyfiles identical before/after;
no schema/dependency change. N3 ordinary UI cutover and full audit remain open.

Previous .25 controls9PASS and Account6PASS; real .24→.25 SW/profile update
identity/history preserved, wrong-key inline denial visible; correct retry was NOT
RUN in that specific upgradeprofile due harness locator, independently PASS on.25.

Текущие результаты исправлений (предыдущие строки initial FAIL ниже исторические):

| Bug | Current status | Fix / independent evidence |
|---|---|---|
| ACCOUNT-WRONG-KEY-01 | PASS .25 | bd380ab; deployed Account6checks incl wrong→correct retry/history isolation |
| NODE-SCANNER-CANCEL-01 | PASS .25 | bd380ab; denied/real running/delayed camera cancel+reopen |
| NODE-QR-01 | PASS .25 | bd380ab; requested catalog NodeQR+copy, pin retained |
| UI-SHARE-CREATE | PASS navigation .25 | bd380ab; visible modal/create/back; new contact handshake separate |
| PENDING-BACK-01 / UI-PUBLIC-ACCEPT-NAV | PASS navigation .25 | bd380ab; single Back, logged-in pending entry |
| PUBLIC-REQUEST-LOADING-01 | PASS .26 visibility/queue | 3c51360; durable request before PoW, truthful saved card; cancel/lifecycle guards and real fresh pair pass |
| ACCOUNT-DELETE-01 | FAIL | Registry removal does not erase selected history from shared vault; previous early PASS withdrawn |
| ROUTE-READY-01 | OPEN | Eventual v3 message success does not prove immediate readiness |
| KEY-EXCHANGE-NO-FEEDBACK-01 | PASS .27 | Initial open button + visible pending/error state; real deployed key exchange and bidirectional messages 16/16 |
| FLIPLOCK-MISSING-01 | PASS .27 | Both Account and global settings OFF→ON→OFF via real deployed UI; physical mobile orientation NOT RUN |
| CONTACT-OWNER-MISMATCH-01 | PASS .28 for saved-owner guidance/retry | User screenshot .26; dd357e1 exact encrypted-flow diagnosis; 7/7 deployed supplemental UI PASS. Real remote owner-conflict delivery NOT RUN |
| RECORDED-NOTE-QUEUE-01 | FAIL .26; .27 NOT RUN | User `Recorded-note queue full`; deployed .26 synthetic 2.3 s voice took ~54 s, delivered but open sender still ⌛ until chat reopen; third immediate recording hit queue-full and was discarded. S-TURN media redesign pending. No storage reset |
| S-TURN-HEALTH-01 | OPEN | EMS real WSS ticket + forced relay 32 KiB/hash PASS; advertised health still TCP-only; call/file/recorded-note UI acceptance NOT RUN |

## Текущая интеграция (не deployed UI)

Source a70ebb9: exact UNIT280 backend+11 Origin+JS suites PASS. Real local
Worker/Account IndexedDB fixture проверяет proof-gated activation, но обычные UI
contacts ещё v3. Lead review выявил same-Host Account-switch: one-time verifier
был привязан к одному journal; исправлено fixed branded router в b9e405f, root
independent browser25checks PASS включая sameHost A→B→A и rootrestore.
Managed raw inbox/ACK/submit заблокированы; owner-bound APIs и post-await token
cleanup добавлены. Rotation пока failclosed/unsupported; renewal/migration и
ordinary adapter остаются открыты. Evidence: qa-ownership-lead-combined.json.

.26 immutable source-overlay pending cancel rerun: harness FAIL (15s locator),
видимый результат уже REQUEST_SAVED+одна waiting card, pageerrors[]. Preparation
успела закончиться до клика; это не подтверждённый product cancellation bug и не
PASS cancel. Evidence пока `/tmp/dmash-browser-tools/qa-remaining26.json`, SW blocked.
Отдельный pending-controls run exit0:4 actual UI PASS (read-close, Accept cancel,
decline cancel, decline confirm), pageerrors[], source hashes сверены с3c51360.
Evidence `docs/evidence/2026-10-08/qa-pending26-controls.json`; SW BLOCKED, real EMS.

N5 source finding: Core legacy `DeviceRoot.deviceMaterial('ml-kem-768-v1')`
делит static KEM material между Accounts одного root; signed V2 pairing rejects
одинаковые participant keys. Owner qa_account_media: explicit per-Account key
migration with preserved legacy decrypt material required, no regeneration/reset
of existing key. Same-root UI upgrade acceptance ещё NOT RUN.

Deployed .26 повторный полный доступный UI03–UI06/UI14 harness88086:26
functional controls PASS, page/SW.26, errors[], exit0. Биометрия проверена только
empty/wrongkey без authenticator, camera только denied/cancel; physicalWebAuthn,
password/replay и full inventory остаются NOT RUN. Static inventory localWIP
отделён от deployed actions. Evidence `qa-controls-deployed26.json`; отдельная
read-only sourceverification214 files соответствует runtime3c51360.

Deployed `.26` UI01 calculator: fresh synthetic profile, 24/24 actual button
flows PASS, page/SW обе `.26`, включая 0–9, арифметику, ошибки, master/wipe,
неверный PIN, unlock, reload lock и wipe только созданного тестового профиля.
Evidence `docs/evidence/2026-10-08/qa-calculator-deployed26.json`; остальные
UI01 settings/biometric controls учитываются отдельными проверками, поэтому
полный UI01 остаётся NOT RUN.

Source `a4fd2aa` Account lifecycle: независимый browser UI29/29 PASS,
page.26 и SW BLOCKED, 56 loaded assets exactSHA; saved text/audio/history/password,
master rewrap и logout реально нажаты. Дополнительная browser-инструментация
проверила wrong-key in-flight write и root preservation, но не заменяет отдельный
видимый wrong-key flow. Исторический Account journal Browser PASS; ordinary v4
Account UI/Node Host пока NOT RUN. Evidence: `qa-account-lifecycle-exact-a4fd2aa.json`
и `qa-account-lifecycle-manifest.json`. Баг session logout hook в позднем
`runtime_fixes.js` исправлен в `efbc9c4` и повторно проверен click/abort-before-key-zero;
это source-overlay retest, deployed `.26` не менялся.

Inactive N4 foundation `3474eee` на exact checkout: UNIT280 backend+11 Origin+
78 JS PASS; Chromium/IDB mechanism PASS (reopen, fault/abort, conflicting writes,
corruption, Account isolation, encrypted rows, binding migration denial). Это не
ordinary chat UI и не двухсторонний Node recovery. Evidence:
`docs/evidence/2026-10-08/qa-n4-foundation-3474eee.json`.

Inactive private Node bootstrap/archive `382db71`: exact UNIT280 backend+11 Origin+
79 JS PASS, независимый local Chromium/IDB PASS; отдельный агентский real
Python→Worker REQUEST/receipts и expired owner archive PASS. Leader exact Worker
retest ожидается; ordinary UI/public neutral path NOT RUN. Evidence:
`docs/evidence/2026-10-08/qa-node-bootstrap-382db71.json`.

## Правила регистрации результата

Для каждого найденного control создать отдельную строку: ID, экран/state,
label/DOM locator, preconditions, реальный action, expected/actual, PASS/FAIL/
NOT RUN, page/SW version, screenshot/video/log, bug severity/agent, fix SHA и
browser retest. Dynamic menus/modals/disabled/loading/error/cancel тоже controls.
Начальный перечень ниже дополнить DOM/accessibility inventory всех экранов;
групповая строка не заменяет проверку каждой конкретной кнопки.

Сценарии запускать на свежих тестовых browser profiles/Accounts; destructive
wipe/delete/recovery — не на пользовательских данных. Использовать реальный
transport на согласованном target. Mock/console-only/unit result не считается UI
PASS. Synthetic mic/camera допустимы как отдельный вид evidence; physical
mobile/WebAuthn/real camera остаются NOT RUN до проверки подходящей средой.

## Начальная матрица полного обхода

| ID | Область и controls | Что обязательно проверить | Full button audit |
|---|---|---|---|
| UI01 | Calculator/setup/master/wipe/unlock | Цифры, операции, clear/back, master/wipe setup, unlock, неверный ввод, full lock | NOT RUN |
| UI02 | Account | Create/login, errors/retry, logout, switch, recovery, locked different Account | NOT RUN |
| UI03 | Navigation/settings | Все tabs/back/close, dropdown/menu, toggles, подтверждения и cancellation | NOT RUN |
| UI04 | Nodes | Request/add/connect/disconnect/retry/password, missing/wrong/replay, unavailable/loading | NOT RUN |
| UI05 | QR/contact import | Generate/show/copy/link/scan/camera select/cancel/import, no contribution, old version | NOT RUN |
| UI06 | Private/public routes | Create/advertise/list/disable/delete, offline Entry, truthful errors, re-add | NOT RUN |
| UI07 | Public contact | Request/Accept/Confirm/decline/cancel, cards/status/chat visibility, loss/restart | NOT RUN |
| UI08 | Chat | Каждая toolbar/menu кнопка, SEND, empty input, handshake, read/delete/history, two peers | NOT RUN |
| UI09 | Saved Messages/local history | Local send/read/delete/password unlock/lock/change/error; без transport fallback | NOT RUN |
| UI10 | Voice/circle | Start/permission/camera select/SEND/cancel, switch chat/Account, playback/retry/download | NOT RUN |
| UI11 | Calls | Start/incoming/accept/decline/hangup/mute/audio/video switching, timeout/permission, RTC stats | NOT RUN |
| UI12 | Files | Request/consent/reject/progress/cancel/complete/download, integrity/offline/bounds | NOT RUN |
| UI13 | Notification/wake | Settings/consent/click/reconnect/locked neutral display, no Account leaks | NOT RUN |
| UI14 | Remaining dynamic UI | Все controls, найденные после modal/context menu/ошибок и новых feature states | NOT RUN |

## Уже существующий baseline — отдельный от полного обхода

Runtime .24 `ed200730dab2e64fc8446e344ce54dbd37cfeec5` имеет DEPLOYED browser
regression PASS, сохранённый в
[логе](docs/evidence/2026-10-08/dmash-recorded-media-release24-live.log): public
request lost/retry, waiting cards, actual sidebar chat clicks, initial exchange,
messages/ratchet/reconnect, actual recording/SEND/receiving playback, final receipt,
forced TURN start/accept/audio RTP/hangup. Page и active SW .24.

Это важный baseline, **но не проверка каждой кнопки**, поэтому full audit rows
выше пока NOT RUN. Не копировать этот PASS на QR scanner/physical phone/video
call/file/caller ringtone/password/installer и другие непроверенные controls.

Известный observed issue: private route readiness даёт Route unavailable/SOS и
требует retry до initial success. Записать timeline и воспроизведение, назначить
protocol/route агенту; исправление проверять браузером, не увеличением timeout.

## Журнал багов и retest (заполняет команда)

| Bug ID | Control/flow | Repro + actual vs expected | Severity/agent | Fix SHA | Browser retest/evidence |
|---|---|---|---|---|---|
| ROUTE-READY-01 | Public→private route→initial | На .24 до PASS повторялись Route unavailable/SOS; immediate readiness не доказана | Triage / назначить | — | NOT RUN |

Первый следующий этап: агенты собирают полный control inventory и воспроизводят
FAIL; тимлид проверяет критичные flows, распределяет fixes и интегрирует их.
Browser audit и исправления не отменяют полного Node v4 cutover N0–N8/A–M/E6.

## Текущий проход Forge — 8 октября 2026

Source HEAD/origin: `2ee3be9fe05e7844480a194e92b11b18c5e2c04d`, clean до
начала QA harnesses. Host `forgeai.isgood.host`, owner `codex`, branch
`transport-v3`. Это исходный SHA до fixes; текущий runtime checkpoint указан выше.
Python 3.12.14 / Node 24.19.0 / Chromium **156.0.8078.4** / Playwright — новая
изолированная test environment. Browser executable и module устанавливались
вне checkout. Synthetic profiles не используют пользовательские vaults.

Оркестратор отвечает за интеграцию/самостоятельную приёмку. Агенты:
`ui_inventory` — UI03–06/14; `qa_account_media` — UI02/08–13;
`node_audit` — environment, Node/Inbox/ownership/deployed-source evidence.
Оркестратор — UI01 и общий BROWSER_QA/context. Runtime implementation до
завершения первоначального обхода не начиналась.

[qa-calculator.json](docs/evidence/2026-10-08/qa-calculator.json): **24 BROWSER
PASS**, actual clicks, page и active SW `transport-v3-recorded-fragments-20261008.24`.
Отдельные строки для каждой цифры 0–9, +/−/×/÷, ±, %, десятичной точки,
ошибки деления на ноль, short master/wipe, wrong PIN, unlock/reload-lock и
explicit wipe только fresh synthetic profile. Harness: `tools/qa_calculator.cjs`.
Это не закрывает UI01 целиком: master rewrap с сохранностью Account/history,
полная gesture/biometric matrix ещё проверяются. WebAuthn/physical phone NOT RUN.

Остальные QA JSON находятся в работе; ошибки тестового locator и прерванные
проходы не считаются подтверждёнными product FAIL. Свежие Node Inbox/ownership
PASS — дополнительные browser fixtures, не заменяют UI клики. Exact EMS source
205/205 PASS относится к runtime `ed200730dab2e64fc8446e344ce54dbd37cfeec5`;
это не новый deploy и не полная поведенческая приёмка.

| Bug ID | Control/flow | Repro + actual vs expected | Severity/agent | Fix SHA | Browser retest/evidence |
|---|---|---|---|---|---|
| NODE-QR-01 | Directory node → QR | Request Node, затем QR: visible error «Для QR нужен канонический D-MASH #/node URI с NodeID.» вместо QR | P2 / ui_inventory triage; Node descriptor owner далее | — | FAIL initial; retest NOT RUN |

Полный план остаётся ACTIVE/PARTIAL. Git SSH push с Forge пока отклоняется
(publickey); read-only EMS SSH и существующий deploy script доступны. Existing
EMS Git publisher авторизуется на GitHub (dry-run отклонён только fetch-first);
передача exact commit и реальный push пока не выполнялись. Никакого
переноса production runtime на Forge и нового deploy в этом проходе не было.

Свежая reference regression завершилась exit 0: **264 backend + 11 Origin + 67
JS suites PASS**, [лог](docs/evidence/2026-10-08/qa-forge-full-tests.log). Дополнительный
[BROWSER Worker transit](docs/evidence/2026-10-08/qa-node-transit.log) PASS на real
loopback Python N1→Chrome B→Python N2 без обхода/Account у B; disconnect даёт
unavailable, root unlock сохраняет Node identity. Это не ordinary Account v4
приёмка и не production transit. Deployed WSS Worker auth/reconnect также PASS
с независимым SSH pin; полноценная N0–N8 матрица остаётся открыта.

Самостоятельный rerun оркестратора: [27/27 UI PASS](docs/evidence/2026-10-08/qa-account-lead.json)
(отдельный новый synthetic profile, exit 0), совпадает с агентским
[Account/media аудитом](docs/evidence/2026-10-08/qa-account-media-summary.md).
Проверены local SEND/delete/cancel/history password wrong/correct/remove, voice
capture/cancel/SEND/decrypt/native playback, circle cancel, logout/registry/relogin,
master rewrap wrong-old/new/old-deny/new-unlock с сохранением того же Account/history.
Remote contacts/calls/files и полный список controls пока не закрыты.

Preliminary issues под независимым воспроизведением: `PENDING-BACK-01` (две
кнопки НАЗАД, одна не закрывает pending modal без Account); `UI-SHARE-CREATE`
(Account QR→PUBLIC→create пишет в скрытую gate, маршрут не виден). Эти случаи
ещё не исправлены; owner triage `ui_inventory`/`node_audit`, fix/retest NOT RUN.

## Подтверждённые blockers первичного обхода

| Bug ID | Control/flow | Actual / expected | Owner | Fix / retest |
|---|---|---|---|---|
| NODE-SCANNER-CANCEL-01 | Nodes → ДОБАВИТЬ ПО QR → camera denied → ОТМЕНА | `Cannot stop, scanner is not running or paused.`; modal остаётся. Expected закрытие без exception | ui_inventory | Assigned; independent lead reproduction on deployed .24; fix/retest NOT RUN |
| UI-SHARE-CREATE | Account QR → PUBLIC → СОЗДАТЬ PUBLIC ROUTE | Modal закрывается, управление route записано в скрытую gate, остаётся workspace. Expected visible route management | ui_inventory | Assigned; node_audit actual replay; fix/retest NOT RUN |
| PENDING-BACK-01 | Logged-out global pending requests → legacy НАЗАД | Две кнопки НАЗАД; legacy action оставляет modal. Expected один работающий back | ui_inventory | Assigned; exact final browser repro/retest pending |

Точечные fixes этих blockers разрешены для продолжения первичного обхода.
Это не начало N3 feature cutover и не отмена оставшихся controls/flows.
NODE-QR-01 требует корректного проверенного Node descriptor; нельзя лечить
ошибку генерацией NodeID или недоверенным TOFU pin.

`ACCOUNT-WRONG-KEY-01` — **P1 confirmed**, owner `qa_account_media`.
Независимый [lead baseline](docs/evidence/2026-10-08/qa-account-lead-lifecycle-baseline.json):
выбрать сохранённый Account → неверный непустой key → ВОЙТИ; фактически виден
workspace вместо отказа, затем правильный key возвращает старую историю.
9 остальных lifecycle checks PASS, 1 expected product FAIL, exit 1. Actual UI
проверил также два Account и изоляцию истории, remove cancel/confirm.
Прежний removal-history-erased PASS отозван: assertion мог выполняться до
асинхронного render; awaited retest выполняется отдельно. Удалялись только synthetic Accounts.
Fix должен сверять сохранённую identity до session/vault/registry mutation;
полный browser retest после интеграции обязателен.

`UI-PUBLIC-ACCEPT-NAV` — **confirmed FAIL**, owner `ui_inventory`:
реальный public Request получен, но global pending→Accept→Quick Name→saved Account
возвращает «Откройте выбранный Account и повторите принятие запроса». После обычного
входа в Account нет доступного перехода к pending. Private QR pairing позволяет
продолжить остальной аудит, но не закрывает public acceptance.

## N5 finding during N3 codec review

`CRYPTO-DISCOVERY-01` (P1, Account agent): existing JS DiscoveryCertificate
accepts route signing key identity-point and forged signature R=identity,S=0.
Lead reproduced against actual bundled NaCl and route_discovery_v4; PyNaCl
reference rejects. This is malformed route-authority acceptance, not evidence
of forgery under an existing honest pinned Account key. New pairing codec
blocks it, but that inactive module alone does not repair active discovery.
Shared JS/Python certificate/response guards and adversarial parity tests in
progress; browser real transport retest required before closing. No live
production attack attempted.

## Recorded voice baseline — deployed .26

| Bug ID | Control/flow | Actual / expected | Owner | Fix / retest |
|---|---|---|---|---|
| VOICE-QUEUE-LOSS-01 | Real peer → record 2.3s → SEND three times | Third SEND shows `Recorded-note queue full`; recording not retained. Expected durable pending note or recoverable retry/cancel | qa_account_media | Confirmed FAIL; S-TURN fix pending |
| VOICE-STALE-STATUS-01 | SEND → authenticated completion → sender open chat | History DELIVERED and outbox removed; visible ⌛ persists until chat reopen. Expected visible final receipt without navigation | qa_account_media | Confirmed FAIL three times; fix/retest pending |
| VOICE-SLOW-TRANSFER-01 | Fresh paired voice 2.721s | ~54s queued-to-ready; burst first profile-to-complete ~64s. Expected fast voice delivery with truthful progress | qa_account_media | Confirmed performance baseline, not isolated encryption timing; S-TURN retest pending |

Evidence and exact-source limits: [voice baseline](docs/evidence/2026-10-08/qa-sender-voice-summary.md).

`NODE-REMOVED-RETRY-01` — confirmed **FAIL**, owner assignment pending (`ui_inventory` triage): deployed `.27`, exact PWA `637c9bb02c2c57a05e8edc815678b6fb204f632c`; global Nodes → add unavailable loopback WSS → Connect → Connect retry → Delete cancel → Delete confirm. Card disappears but WebSocket attempts rise 3→5 during the following3.5s. Fresh synthetic profile, no Account/EMS/PoW, no page errors;61 captured JS responses exact-match. [Evidence](docs/evidence/2026-10-08/qa-node-unavailable-local27.json):5 controls PASS, remove-stop-retry FAIL. Earlier `.26` harness expected transient ERROR rather than observable RECONNECTING; those state assertions were harness assumptions, not product failures.

Read-only localization: `NodeManager.connectEndpoint` replaces a disconnected connection object without clearing its old reconnect timer. `scheduleReconnect` timer calls `connectEndpoint` without checking current generation or endpoint membership; deleting the newer map entry leaves the replaced object's callback able to reinsert the removed Node. This is a source-supported hypothesis for the observed retry, requiring narrow lifecycle regression and actual browser retest. No product patch included.

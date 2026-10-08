# Browser-first QA — текущий аудит Forge

Требование пользователя от 8 октября 2026: всё тестировать браузером; перед
новой разработкой проверить каждую кнопку, найти баги, назначить агентам,
исправить и провести повторную приёмку. Тимлид/оркестратор сам отвечает за
интегрированный результат. Этот файл — журнал и начальная матрица, не утверждение,
что полный обход UI уже выполнен.

## Актуальный release checkpoint

Актуальная опубликованная PWA: **`d9faf9b93d0aa6f3440560ffc31227b5f9c089e2`**,
page и active controlling SW `.33` в двух новых synthetic Chromium profiles.
Независимый [deployed `.33` video/mobile gate](docs/evidence/2026-10-08/qa-media33-root-deployed.json):
video **21/21 PASS** (39 encoded/38 decoded RTP frames через TURN, камера
off/re-enable/switch и permission denial modal), mobile **19/19 PASS**
(реальные звонок, файл с download SHA, голосовое и кружок), 130/130
загруженных source responses в каждом прогоне exact SHA, page errors 0.
Read-only production verifier: 212/212 PWA files, missing/changed/extras 0.
Android пользователя и intermittent voice latency остаются OPEN, равно как
автоматический приём файла и долговечный inline chat file. Production backend,
identity и базы `.33` не менял.

Предыдущая опубликованная PWA: **`042d5803d5d622da72848c67d96bd5c8243c4819`**,
page и active controlling SW `.32` в двух новых synthetic Chromium profiles.
Независимый [deployed `.32` voice/file gate](docs/evidence/2026-10-08/qa-voice-file32-deployed.json):
**24/24 PASS**, 128/128 обычных загруженных response bodies совпали с exact SHA,
page errors и console warnings/errors 0. Отдельно в обоих профилях сверены
served и active SW CacheStorage SHA-256 для `call_admission_worker.js` и
импортируемого `resource_pow.js`; реальный Worker вернул proof, независимо
проверенный WebCrypto. Через действительный EMS/S-TURN после UI создания двух
Account, PRIVATE QR, контакта, обмена ключами и текста голосовая запись 30 532
байта расшифрована получателем, отправитель получил `DELIVERED` и освободил
локальные байты. От нажатия отправки до квитанции прошло **4,127 с**,
WSS ticket занял **2,052 с** на этом desktop Chromium. Пользователь сообщил,
что на физическом Android `.31` голосовая доставка занимала более минуты;
этот Android на `.32` ещё не измерен. Предыдущий fresh desktop browser `.31`
показал 11,625 с stop→DELIVERED и 9,489 с WSS ticket — сравнение разных
challenge/состояний сети, не обещание постоянного ускорения.

Файл **1 МиБ + 13 байт** получен и скачан с тем же SHA-256, обе стороны
сохранили «Передано и проверено». Поздняя нативная ошибка DataChannel спустя
91 мс после проверенного завершения не перезаписала успех.
[Совмещённый source-overlay gate](docs/evidence/2026-10-08/qa-voice-file32-source-overlay.json)
на том же exact candidate: 20/20 PASS, 140/140 exact bodies, SW blocked, real
transport; voice 2,480 с, WSS ticket 464 мс, файл и download SHA PASS.
В первом deployed прогоне все 24 UI/Worker checks прошли, но общий сборщик
response bodies попытался прочитать уже закрытый короткий test Worker и дал
harness FAIL. Чистый повтор проверил Worker-ресурсы отдельным served/cache hash
gate и завершился exit 0. На `.31` реальный file repro был FAIL: отправитель
успешен, получатель сменил успешный статус на `File channel failed` после
поздней ошибки канала; исправление terminal monotonicity `c59170f` и ускорение
admission PoW `1c87123` входят в `.32`. Результаты не закрывают N0–N8,
полный N4 recovery, ordinary Node UI и физический мобильный тест.
Отдельный [deployed `.32` video toggle red](docs/evidence/2026-10-08/qa-video32-deployed-red.json):
при реальном аудиозвонке через relay кнопка 📷 после клика не вызвала запрос
камеры и не создала ни локальный видеотрек, ни удалённый видеоприёмник;
страница/active SW `.32`, звонок и аудио продолжили работу. Статус UI11
video toggle **FAIL**, owner `qa_remaining`, source-overlay fix на проверке.

Предыдущая опубликованная PWA: **`be6a1d9a58ba9fffeb0daad234a6506e5b269667`**,
page и active controlling SW `.31` в двух новых synthetic Chromium profiles.
Независимый [deployed `.31` media gate](docs/evidence/2026-10-08/qa-private-media31-deployed.json):
**22/22 PASS**, 268/268 загруженных response bodies совпали с exact SHA,
page errors и console warnings/errors 0. Реальными UI actions созданы два
Account, подключены Node, скопированы PRIVATE QR, импортированы pairing packages
через `[ + ]`, открыты чаты, выполнены обмен ключами и отправка текста.
Голосовая запись и кружок нажаты/записаны/отправлены и расшифрованы получателем;
оба локальных sender intent получили `DELIVERED`, содержимое после квитанции
освобождено. Для voice тест намеренно добавил к Data URL параметр codec в кавычках
и задержал FileReader на 1,8 с: callback отработал при открытом «Избранном»,
показанного пользователю modal не возникло, запись доставлена исходному peer.
После реальной перезагрузки, Master и Account login на обоих профилях page/SW
остались `.31`, в каждой истории ровно одна voice и один circle, обе квитанции
сохранились. Это synthetic mic/camera и synthetic MIME header; фактический MIME
Android пользователя и физические устройства ещё не проверены. Перед исправлением
alias source-overlay [воспроизвёл](docs/evidence/2026-10-08/qa-private-media31-red.json)
modal `ЗАПИСЬ НЕ ОТПРАВЛЕНА / Cannot read properties of undefined (reading 'getAlias')`
после durable intent; [повторный source-overlay](docs/evidence/2026-10-08/qa-private-media31-green.json)
прошёл 20/20. Исправления: MIME `1199fbd`, captured history alias `fef56a3`,
интегрированы в опубликованный exact SHA выше.

Предыдущий опубликованный checkpoint **`22c699d6575fe2ba977db44264d8df0062b14799`**
(page/active SW `.30`): независимый [browser history gate](docs/evidence/2026-10-08/qa-history-counter-deployed30.json):
PUBLIC Request/Accept/Confirm, реальная кнопка обмена ключами, двусторонний
текст и FlipLock **19/19 PASS**; 138/138 загруженных response bodies совпали
с exact SHA, page errors 0. Контролируемая synthetic предпосылка добавила
одну ранее сохранённую строку в чат через Storage; перед нажатием кнопки её
счётчик был 1. После обмена эта история видима в UI, счётчик остался 1; после
отправки/получения сообщений история осталась и счётчик стал 3. Это реальная
UI приёмка сохранности поверх fixture, не проверка recovery N4 или миграции
existing user vault. Первый прогон этого сценария ошибочно ожидал видимый log
до initial key exchange; это harness assumption, не продуктовый FAIL.
Ведущий сообщил exact EMS verifier 256/256 после deploy; независимый browser
hash gate приведён выше. [Оставшаяся матрица](docs/evidence/2026-10-08/qa-remaining-deployed29-plan.md)
активна: ordinary Account→NodeRuntimeHostV4, full N4 recovery/migration,
N0–N8/A–M/E6 и полный UI01–UI14 не DONE.

На предыдущем exact `5a2439834a2fc22db8f6ecd0b9674d533397ea8a`, page/SW
`.29`, [дополнительный browser-first проход](docs/evidence/2026-10-08/qa-remaining-deployed29.json)
дал calculator 24/24, local Saved Messages/media/master 27/27, Node/QR/navigation
9/9 и node removed retry 6/6 PASS; Account lifecycle 9 PASS / 1 FAIL
(`ACCOUNT-DELETE-01`). Fresh two-profile [calls/files gate](docs/evidence/2026-10-08/qa-call-file-deployed29.json)
с 142/142 exact loaded responses: PUBLIC/key/text/FlipLock и relay call
decline/accept/mute/speaker/hangup PASS; video toggle и 1 МиБ+13 байт file
complete FAIL. Последний показал отправителю «Передано и проверено»,
получателю `File channel failed`; причина late DataChannel error после verified completion
затем воспроизведена на `.31` fresh PRIVATE pair. На `.31` video call и Account
deletion остались **NOT RUN**. Исторические `.28`/`.27`/`.26` evidence
остаются ниже; `ROUTE-READY-01` OPEN, physical mobile/WebAuthn NOT RUN.

Текущие результаты исправлений (предыдущие строки initial FAIL ниже исторические):

| Bug | Current status | Fix / independent evidence |
|---|---|---|
| ACCOUNT-WRONG-KEY-01 | PASS .25 | bd380ab; deployed Account6checks incl wrong→correct retry/history isolation |
| NODE-SCANNER-CANCEL-01 | PASS .25 | bd380ab; denied/real running/delayed camera cancel+reopen |
| NODE-QR-01 | PASS .25 | bd380ab; requested catalog NodeQR+copy, pin retained |
| UI-SHARE-CREATE | PASS navigation .25 | bd380ab; visible modal/create/back; new contact handshake separate |
| PENDING-BACK-01 / UI-PUBLIC-ACCEPT-NAV | PASS navigation .25 | bd380ab; single Back, logged-in pending entry |
| PUBLIC-REQUEST-LOADING-01 | PASS .26 visibility/queue | 3c51360; durable request before PoW, truthful saved card; cancel/lifecycle guards and real fresh pair pass |
| ACCOUNT-DELETE-01 | FAIL deployed `.29`; `.31` NOT RUN | Real synthetic UI removal promises complete erasure, but recreating same Account reveals previous local history; P1, owner TBD, preserve profile for fix/retest |
| ROUTE-READY-01 | OPEN | Eventual v3 message success does not prove immediate readiness |
| KEY-EXCHANGE-NO-FEEDBACK-01 | PASS `.30` | Initial open button + visible pending state; exact22c public pair completes and sends text both ways |
| FLIPLOCK-MISSING-01 | PASS `.30` | Account/global settings OFF→ON→OFF via real deployed UI; physical mobile orientation NOT RUN |
| CONTACT-OWNER-MISMATCH-01 | PASS .28 for saved-owner guidance/retry | User screenshot .26; dd357e1 exact encrypted-flow diagnosis; 7/7 deployed supplemental UI PASS. Real remote owner-conflict delivery NOT RUN |
| RECORDED-NOTE-QUEUE-01 | PASS deployed `.31` voice/circle | Fresh PRIVATE pair actual SEND, durable sender intent, receiver decrypt and final `DELIVERED`; older `.26` queue-full was historical, no universal latency claim |
| RECORDER-MIME-31 / RECORDER-ALIAS-31 | PASS deployed `.31` scoped | Valid quoted codec parameter accepted without changing recorded bytes; delayed callback over Saved Messages no modal, original peer received; normal and locked-chat alias UNIT PASS, physical Android MIME/locked-chat browser NOT RUN |
| MEDIA-LOADER-ANDROID-33 | PASS deployed `.33` scoped; physical Android NOT RUN | User `.32` screenshots showed call/file `CallSignalingSession` TypeError and pending circle. Synthetic mobile startup seam reproduced red and candidate 19/19 green; independent `.33` source seam 19/19 green on repeat after one intermittent voice timeout. Exact deployed normal mobile fresh PRIVATE UI 19/19 PASS: call connected, file download SHA, voice/circle delivered/decrypted; 130 loaded source responses exact SHA, page/active SW `.33`, page errors 0. [Red/green seam](docs/evidence/2026-10-08/qa-media-loader32-mobile.json), [deployed evidence](docs/evidence/2026-10-08/qa-media33-root-deployed.json). Android phone retest still needed. |
| VIDEO-TOGGLE-32 | PASS deployed `.33` scoped; physical Android NOT RUN | `.32` audio call camera button was inert. `.33` actual UI 21/21 PASS on fresh PRIVATE pair: camera requested on click, 39 encoded/38 decoded RTP frames via TURN relay, off/re-enable/switch and permission-denied modal/OK, audio maintained, fingerprint stable, clean hangup; 130 loaded source bodies exact SHA, page/active SW `.33`, page errors 0. [Candidate evidence](docs/evidence/2026-10-08/qa-video32-candidate.json), [deployed evidence](docs/evidence/2026-10-08/qa-media33-root-deployed.json). |
| MEDIA-ROOT-33 | PASS deployed scoped; intermittent voice latency OPEN | Independent exact `.33` source video 21/21 and deployed video 21/21 PASS with real TURN RTP; deployed mobile 19/19 PASS with call/file hash/voice/circle, page and active SW `.33`, 130/130 loaded source bytes each, page errors 0. One source seam run stalled voice for 180 s after 17 prior passes; fresh instrumented source seam 19/19 PASS. Cause unknown, physical Android NOT RUN. [Source metadata](docs/evidence/2026-10-08/qa-media33-root-source.json), [deployed metadata](docs/evidence/2026-10-08/qa-media33-root-deployed.json). |
| N7-FILE-INLINE-AUTO-01 | FAIL existing `.32`; owner qa_remaining | Confirmed peer still sees per-file «Принять», file exists only in ephemeral transfer panel, and closing it revokes the only Blob URL. User requires automatic encrypted receipt and durable inline chat file/preview/open with retained sender intent/status; no silent OS download. Separate Account-owned storage, quota and authenticated ACK-after-commit candidate in progress. Retest UI auto receive/reload/offline/cancel/limits, two Accounts, no data loss. |
| NODE-REMOVED-RETRY-01 | PASS deployed `.29`; `.31` NOT RUN | Fresh browser 6/6, exact5a JS62/62, zero new loopback sockets for 3.5 s after removal |
| S-TURN-HEALTH-01 / N7-FILE-TERMINAL-32 | PASS deployed `.32` scoped | 1 МиБ+13 байт file receiver/download SHA PASS after late DataChannel error; sender/receiver visible verified final, 24/24 deployed gate. Video toggle FAIL deployed `.32` (UI click no camera request/track); fix pending |
| ADMISSION-LATENCY-32 | PASS desktop Chromium; Android NOT RUN | Same fixed difficulty-18 transcript Worker proof: 979→264 мс, identical counter and independent digest. Deployed `.32` voice stop→DELIVERED 4,127 с, WSS ticket 2,052 с; physical Android >1 min is user-reported on `.31`, not a browser measurement |

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

`NODE-REMOVED-RETRY-01` — confirmed **FAIL** deployed `.27`, exact PWA `637c9bb02c2c57a05e8edc815678b6fb204f632c`; global Nodes → add unavailable loopback WSS → Connect → Connect retry → Delete cancel → Delete confirm. Card disappears but WebSocket attempts rise 3→5 during the following3.5s. Fresh synthetic profile, no Account/EMS/PoW, no page errors;61 captured JS responses exact-match. [Evidence](docs/evidence/2026-10-08/qa-node-unavailable-local27.json):5 controls PASS, remove-stop-retry FAIL. Agent `node_retry_cleanup` fix `d34b1b6` preserves direct NodeEndpoint interop and retires replaced timers/clients; [source-overlay retest](docs/evidence/2026-10-08/qa-node-removed-retry-direct-source27.json) 6/6 PASS, zero post-delete sockets over3.5 s. Published source includes fix; production PWA `.28` still has old node_manager.js, so DEPLOYED retest remains NOT RUN.

Read-only localization: `NodeManager.connectEndpoint` replaces a disconnected connection object without clearing its old reconnect timer. `scheduleReconnect` timer calls `connectEndpoint` without checking current generation or endpoint membership; deleting the newer map entry leaves the replaced object's callback able to reinsert the removed Node. This is a source-supported hypothesis for the observed retry, requiring narrow lifecycle regression and actual browser retest. No product patch included.

## UI01 calculator exact .27 acceptance

[24/24 controls PASS](docs/evidence/2026-10-08/qa-calculator-exact27.json): minimum-length master/wipe setup, ten digit buttons, four arithmetic operators, sign, percent, repeated decimal, divide-by-zero visible error, wrong PIN, correct unlock, reload relock, destructive wipe returning to fresh setup. Wipe used only a fresh synthetic profile without user data or Node connection. Both page/SW `.27`; loaded JS bytes checked against `637c9bb02c2c57a05e8edc815678b6fb204f632c`; no browser errors or sockets. This does not claim Account migration/recovery or physical biometric acceptance.

## Local input error controls exact .27

[4/4 PASS](docs/evidence/2026-10-08/qa-local-input-errors27.json), fresh synthetic Account,390×844 emulation: actual attachment button/file chooser with synthetic text file → explicit unsupported-local-file notice and no message; microphone → visible `МИКРОФОН / ОТКАЗАНО`; circle → `КАМЕРА / Не удалось запустить камеру.`; both errors acknowledge with OK and restore idle toolbar; empty SEND creates no row and keeps input usable. Camera/microphone unavailable in headless profile: this is an error-path check, not physical permissions/capture acceptance. Page/SW `.27`,61 JS responses exact `637c9bb02c2c57a05e8edc815678b6fb204f632c`, no sockets or browser errors. Physical mobile, remote file consent/progress/cancel and S-TURN remain NOT RUN here.

## Contact modal controls exact .27

[6/6 PASS](docs/evidence/2026-10-08/qa-contact-modals27.json): import Cancel; malformed import explicit error with no contact creation; empty import creates no contact; PRIVATE pairing view/Close; empty PUBLIC view with create control/Close; Account biometric wrong-secret rejection with no enrollment. Fresh synthetic Account, no Node/PoW/socket;61 JS responses exact `637c9bb02c2c57a05e8edc815678b6fb204f632c`, page/SW `.27`, no page errors. Clipboard contents, real QR camera scan, route creation/registration, remote Request/Accept/Confirm and real biometric remain outside this slice.

Account recovery remains NOT RUN in this inventory: an authenticated root-loss/state-migration fixture and preserved identity/history comparison are required. No console mutation or nonexistent generic recovery button is being presented as user-flow acceptance. Calls/files require separate real paired transport; retained synthetic CDP9452 is held unchanged for S-TURN handoff, and user CDP9449 is untouched.

## Independent S-TURN ordinary UI candidate acceptance

[Detailed matrix and evidence](docs/evidence/2026-10-08/qa-media-candidate29-summary.md), exact source `a524bc0520013e6311158faac980774c5dc86efb`, page `.29`, SW BLOCKED, real EMS with both capabilities true. Fresh synthetic PUBLIC pair;138 response bodies and100 post-reload script sources verified. Voice burst/durable save/visible final receipt/receiver decode+hash/noautoplay/relay path PASS; circle cancel/SEND/delivery/distinct decrypt/playback PASS; offline persistence and Account switch isolation PASS.

`NOTE-RELOAD-CONTROLS-01` — **PRODUCT FAIL**, owner `qa_account_media`: pending note survives reload but only generic ОЖИДАЕТ is visible, with no cancel/retry controls. New hydration fix needs independent exact-candidate retest. `NOTE-SEND-RESPONSIVENESS-01` — **OPEN**: one intended2.3s capture became7.591s; stop-to-durable6.764s. Timing may include admission/UI/CDP contention; fast-send acceptance remains open. Reconnect exceeded the original90s observation, then eventually delivered at attempt4; preserve both facts. Old pending-fragment migration, durable cancel/retry and large-note consent remain NOT RUN in this slice. Original locator assumptions/failures remain classified separately in the matrix rather than converted into product PASS.

## Media-side corrected candidate retest (not final integrated/deployed SHA)

[31/31 PASS on exact946bb527](docs/evidence/2026-10-08/qa-media-final946-summary.md), fresh synthetic PUBLIC pair, page `.29`, SW BLOCKED,207 loaded responses exact-match, no page errors. `NOTE-RELOAD-CONTROLS-01` now PASS: actual visible cancel after reload retains note; actual retry and bounded OFF→ON recovery succeed. Account isolation, voice burst, hash/relay/no-autoplay, circle capture/SEND/decode/playback PASS. Prior a524 failures remain historical evidence. SEND→durable188/349/390ms; earlier6.764s delay not repeated in this sample. Measured payload/metadata/RTC counters do not prove server-GB savings. Legacy pending migration NOT RUN because retained9452 endpoint is unavailable; no reset/downgrade. Intended integrated PWA requires separate exact-SHA acceptance.

## Final integrated source gate: media6e9 + deletion668 (not deployed)

[Integrated UI matrix](docs/evidence/2026-10-08/qa-integrated-delete668-summary.md): exact6e9 media PUBLIC/key/text/voice burst/hash/relay/reload/cancel/retry/Account switch/circle controls PASS across initial run and same-profile continuation. Original async gate TEST race remains recorded;205 source responses match6e9, page `.29`, SW BLOCKED.

`CHAT-DELETE-PREFLIGHT-UI-01` — red3e actual Delete→ДА preserves Storage history but revokes peer/route before refusal and emits no visible error. Exact668 retest **PASS**: visible «УДАЛЕНИЕ НЕ ВЫПОЛНЕНО», no changed peer/history/owner/media/epoch/route; Cancel PASS; valid deletion removes target and preserves unknown opaque row.128 red +129 green loaded responses exact; both identities retained on reload, no green page errors. Core fix efb1b0d integrated668. This and Storage preflight15d2d07 are **N4 safety-only**; versioned-row IDB mechanism PASS does not close full N4 migration or ordinary recovery. Actual published page/SW acceptance remains integrator work.

## DEPLOYED exact5a page + active SW .29 acceptance

**Текущий независимый DEPLOYED UI gate:** exact `5a2439834a2fc22db8f6ecd0b9674d533397ea8a`, actual HTTPS EMS, page и active controlling SW `.29`, без overlay. PUBLIC Request/Accept/Confirm, key/text в обе стороны, voice burst/hash/relay/decrypt/playback, offline/reload/visible cancel/retry/Account switch/reconnect, circle и безопасное удаление контакта PASS на свежей synthetic паре. Исходное прерывание Settings входящим notification сохранено; после actual OK тот же профиль прошёл 27/27 continuation checks.206 loaded responses exact (122 from SW), pageerrors0. SEND→durable203/251/263ms; все три delivered через45.641s после первого durable save — это не обещание постоянной скорости доставки. Corrupt-owner refusal сохраняет history/keys/media/route/epoch; valid deletion сохраняет unknown opaque row и identity. [Матрица и ограничения](docs/evidence/2026-10-08/qa-deployed5a-summary.md). N4 safety-only, не full recovery/migration. Legacy pending migration NOT RUN (CDP9452 unavailable); user9449 untouched, synthetic9490 retained. Full N0–N8/A–M/E6 и оставшиеся controls не объявлены DONE.

Bug retest owners: `NOTE-RELOAD-CONTROLS-01` / recorded-note UI — qa_account_media, deployed PASS; `CHAT-DELETE-PREFLIGHT-UI-01` — Storage/Core owners, deployed PASS; initial incoming-notification Settings interruption remains a preserved QA control observation, handled with actual OK on the same profiles. No physical authenticator or full recovery claim. The previous source-only gates above remain historical, not alternate deployed targets.

## Дополнительный deployed `.29` browser-first проход

Новые fresh synthetic Chromium profiles; пользовательский CDP9449 и retained
synthetic CDP9490 не открывались. Page и active controlling SW во всех пяти
прогонах — `transport-v3-node-preparation-20261008.29`. Источник приложения —
`5a2439834a2fc22db8f6ecd0b9674d533397ea8a` (дальнейший `df59bb9`
изменил QA/docs, но не PWA). [Компактный журнал действий](docs/evidence/2026-10-08/qa-remaining-deployed29.json)
не содержит Account IDs, credentials или plaintext из браузерного хранилища.

| Slice | Actual UI actions / result | Limits |
| --- | --- | --- |
| UI01 calculator | 24/24 PASS: все цифры/операторы, short master/wipe, wrong/unlock, reload lock и wipe только пустого synthetic профиля | Physical orientation/WebAuthn NOT RUN |
| UI02 Account lifecycle | 9 PASS / 1 FAIL: два синтетических Account, wrong→correct, switch/history isolation, registry remove cancel/confirm | `ACCOUNT-DELETE-01` ниже |
| UI03–06 navigation/Node/QR | 9/9 PASS: real WSS request, Node QR/copy, public route UI, camera denied/running/delayed cancel/reopen, pending Back и global node pin | Private/password Node и route readiness NOT RUN |
| UI09/local UI10/UI12/master | 27/27 PASS: Saved Messages text/password wrong/correct/remove/delete, voice capture/cancel/decrypt/play, circle cancel, unsupported local file notice, master rewrap + retained Account/history | Remote calls/files and physical devices NOT RUN |
| `NODE-REMOVED-RETRY-01` | 6/6 PASS: unavailable WSS add/dedupe, Connect/retry remain RECONNECTING, Delete dismiss/accept; after removal no new socket for 3.5s | Loopback negative flow only; 62 loaded JS responses match exact source SHA; page errors 0 |

`ACCOUNT-DELETE-01` — **FAIL deployed `.29`, P1 privacy/UX, owner TBD**.
На fresh test profile создать Account A и B, в B через «Избранное» отправить
синтетическое локальное сообщение; выйти, открыть global Account manager,
нажать «УДАЛИТЬ АККАУНТ» для B. Cancel сохраняет B. Повторить, ввести
`УДАЛИТЬ`, подтвердить; строка B исчезает из registry. После «+ НОВЫЙ ВХОД»
создать B с тем же идентификатором и паролем, открыть «Избранное»: прежнее
сообщение видно. Проверка ждала конкретный текст в chat DOM, это не гонка
локатора. Prompt обещает «Вся история будет стерта!», success — «аккаунт и его
ключи полностью ликвидированы», поэтому фактическая сохранность противоречит
действующему UI-контракту. Исправление требует owner-aware preflight и проверки
соседнего Account; не удалять production vault ради QA. Fix/retest **NOT RUN**.

`NODE-REMOVED-RETRY-01` — **PASS deployed `.29` для прежнего reproducer**;
исходный `.27` FAIL сохранён выше как история. Это не проверка password/admission
или реального authenticated Node. Прогон Node проверил каждый fetched JS body
по exact `5a24398`; остальные четыре прогона сверили page/active SW build, но
не хешировали все свои response bodies, что явно ограничивает их provenance.
Старый exact verifier и независимая deployed gate дополняют это наблюдение.
Обычная переписка через NodeRuntimeHostV4, полный N4 recovery/migration и
общий inventory UI01–UI14 остаются **NOT RUN** как целостные матрицы.

# Browser-first QA — текущий аудит Forge

Требование пользователя от 8 октября 2026: всё тестировать браузером; перед
новой разработкой проверить каждую кнопку, найти баги, назначить агентам,
исправить и провести повторную приёмку. Тимлид/оркестратор сам отвечает за
интегрированный результат. Этот файл — журнал и начальная матрица, не утверждение,
что полный обход UI уже выполнен.

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
`transport-v3`. Runtime-код пока не менялся: первоначальная инвентаризация открыта.
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
